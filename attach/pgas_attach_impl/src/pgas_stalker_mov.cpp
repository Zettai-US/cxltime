// SPDX-License-Identifier: MIT
// Frida Stalker-based mov instruction interception for CXL PGAS
//
// The Stalker JIT-recompiles every basic block the thread executes.
// Our transformer callback scans each instruction via Capstone:
//   - If the instruction has a memory operand (X86_OP_MEM), we insert
//     a callout BEFORE the instruction.
//   - The callout computes the effective address at runtime from the
//     live register state (base + index*scale + disp).
//   - If the EA falls in [pgas_base, pgas_base+pgas_size), we route
//     the load/store through CXLMemSim and patch the result into
//     the register file so the original mov becomes a no-op (or we
//     skip it entirely by not keeping the instruction).
//
// For stores we intercept BEFORE the mov executes to capture the value.
// For loads we replace the instruction: callout does the remote load
// and writes the result into the destination register directly.

#include "pgas_stalker_mov.hpp"
#include "pgas_cxlmemsim_integration.hpp"
#include <spdlog/spdlog.h>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <vector>
#include <mutex>

using namespace bpftime::attach;

// ---------------------------------------------------------------------------
// Internal context
// ---------------------------------------------------------------------------

struct pgas_stalker_ctx {
    GumStalker *stalker;
    GumStalkerTransformer *transformer;

    pgas_stalker_config_t config;
    pgas_stalker_stats_t stats;
    std::mutex stats_mutex;

    bool active;
};

// Thread-local pointer so callouts can find the context without extra args
static thread_local pgas_stalker_ctx *tls_ctx = nullptr;

// ---------------------------------------------------------------------------
// Helpers: detect if a Capstone instruction has a memory operand in CXL range
// ---------------------------------------------------------------------------

// Information extracted from a mov with a memory operand
struct mov_mem_info {
    bool has_mem_op;       // true if instruction has X86_OP_MEM
    bool is_load;          // true if memory operand is source (load)
    bool is_store;         // true if memory operand is destination (store)
    uint8_t mem_op_idx;    // which operand is the memory operand
    uint8_t reg_op_idx;    // which operand is the register operand
    uint8_t access_size;   // size in bytes (1, 2, 4, 8, 16)

    // Memory operand components (from Capstone)
    x86_reg base_reg;
    x86_reg index_reg;
    int scale;
    int64_t disp;
};

static bool is_mov_insn(unsigned int insn_id) {
    switch (insn_id) {
    case X86_INS_MOV:
    case X86_INS_MOVABS:
    case X86_INS_MOVZX:
    case X86_INS_MOVSXD:
    case X86_INS_MOVSX:
    case X86_INS_MOVNTI:    // Non-temporal store
    case X86_INS_MOVNTDQ:   // Non-temporal store (SSE)
    case X86_INS_MOVNTPS:   // Non-temporal store (SSE)
    case X86_INS_MOVNTPD:   // Non-temporal store (SSE2)
    case X86_INS_MOVAPS:    // Aligned packed single
    case X86_INS_MOVUPS:    // Unaligned packed single
    case X86_INS_MOVAPD:    // Aligned packed double
    case X86_INS_MOVUPD:    // Unaligned packed double
    case X86_INS_MOVDQA:    // Aligned packed integer
    case X86_INS_MOVDQU:    // Unaligned packed integer
    case X86_INS_MOVSD:     // Scalar double
    case X86_INS_MOVSS:     // Scalar single
    case X86_INS_MOVQ:      // Quadword
    case X86_INS_MOVD:      // Doubleword
        return true;
    default:
        return false;
    }
}

static bool analyze_mov(const cs_insn *insn, const pgas_stalker_config_t *cfg,
                        mov_mem_info *out) {
    memset(out, 0, sizeof(*out));

    if (!is_mov_insn(insn->id))
        return false;

    // Filter by config
    if (!cfg->hook_mov &&
        (insn->id == X86_INS_MOV || insn->id == X86_INS_MOVABS))
        return false;
    if (!cfg->hook_movzx &&
        (insn->id == X86_INS_MOVZX || insn->id == X86_INS_MOVSXD ||
         insn->id == X86_INS_MOVSX))
        return false;
    if (!cfg->hook_movnti &&
        (insn->id == X86_INS_MOVNTI || insn->id == X86_INS_MOVNTDQ ||
         insn->id == X86_INS_MOVNTPS || insn->id == X86_INS_MOVNTPD))
        return false;

    const cs_x86 *x86 = &insn->detail->x86;

    // Find the memory operand
    for (uint8_t i = 0; i < x86->op_count; i++) {
        if (x86->operands[i].type == X86_OP_MEM) {
            out->has_mem_op = true;
            out->mem_op_idx = i;
            out->base_reg = x86->operands[i].mem.base;
            out->index_reg = x86->operands[i].mem.index;
            out->scale = x86->operands[i].mem.scale;
            out->disp = x86->operands[i].mem.disp;
            out->access_size = x86->operands[i].size;

            // In x86 AT&T/Intel convention:
            //   mov mem, reg -> load  (operand 0 = mem src, operand 1 = reg dst)
            //   mov reg, mem -> store (operand 0 = reg src, operand 1 = mem dst)
            // Capstone uses Intel syntax: dst, src
            //   mov reg, [mem] -> load  (op0 = reg dst, op1 = mem src)  -> i == 1
            //   mov [mem], reg -> store (op0 = mem dst, op1 = reg src)  -> i == 0
            if (i == 0) {
                // Memory is destination -> store
                out->is_store = true;
                out->reg_op_idx = 1;
            } else {
                // Memory is source -> load
                out->is_load = true;
                out->reg_op_idx = 0;
            }
            break;
        }
    }

    return out->has_mem_op;
}

// ---------------------------------------------------------------------------
// Register <-> GumCpuContext mapping
// ---------------------------------------------------------------------------

#if defined(__x86_64__)
static uint64_t read_reg(const GumCpuContext *cpu, x86_reg reg) {
    switch (reg) {
    case X86_REG_RAX: case X86_REG_EAX: case X86_REG_AX: case X86_REG_AL:
        return cpu->rax;
    case X86_REG_RBX: case X86_REG_EBX: case X86_REG_BX: case X86_REG_BL:
        return cpu->rbx;
    case X86_REG_RCX: case X86_REG_ECX: case X86_REG_CX: case X86_REG_CL:
        return cpu->rcx;
    case X86_REG_RDX: case X86_REG_EDX: case X86_REG_DX: case X86_REG_DL:
        return cpu->rdx;
    case X86_REG_RSI: case X86_REG_ESI: case X86_REG_SI: case X86_REG_SIL:
        return cpu->rsi;
    case X86_REG_RDI: case X86_REG_EDI: case X86_REG_DI: case X86_REG_DIL:
        return cpu->rdi;
    case X86_REG_RBP: case X86_REG_EBP: case X86_REG_BP: case X86_REG_BPL:
        return cpu->rbp;
    case X86_REG_RSP: case X86_REG_ESP: case X86_REG_SP: case X86_REG_SPL:
        return cpu->rsp;
    case X86_REG_R8:  case X86_REG_R8D:  case X86_REG_R8W:  case X86_REG_R8B:
        return cpu->r8;
    case X86_REG_R9:  case X86_REG_R9D:  case X86_REG_R9W:  case X86_REG_R9B:
        return cpu->r9;
    case X86_REG_R10: case X86_REG_R10D: case X86_REG_R10W: case X86_REG_R10B:
        return cpu->r10;
    case X86_REG_R11: case X86_REG_R11D: case X86_REG_R11W: case X86_REG_R11B:
        return cpu->r11;
    case X86_REG_R12: case X86_REG_R12D: case X86_REG_R12W: case X86_REG_R12B:
        return cpu->r12;
    case X86_REG_R13: case X86_REG_R13D: case X86_REG_R13W: case X86_REG_R13B:
        return cpu->r13;
    case X86_REG_R14: case X86_REG_R14D: case X86_REG_R14W: case X86_REG_R14B:
        return cpu->r14;
    case X86_REG_R15: case X86_REG_R15D: case X86_REG_R15W: case X86_REG_R15B:
        return cpu->r15;
    case X86_REG_RIP:
        return cpu->rip;
    case X86_REG_INVALID:
        return 0;
    default:
        return 0;
    }
}

static void write_reg(GumCpuContext *cpu, x86_reg reg, uint64_t val) {
    switch (reg) {
    case X86_REG_RAX: case X86_REG_EAX: case X86_REG_AX: case X86_REG_AL:
        cpu->rax = val; break;
    case X86_REG_RBX: case X86_REG_EBX: case X86_REG_BX: case X86_REG_BL:
        cpu->rbx = val; break;
    case X86_REG_RCX: case X86_REG_ECX: case X86_REG_CX: case X86_REG_CL:
        cpu->rcx = val; break;
    case X86_REG_RDX: case X86_REG_EDX: case X86_REG_DX: case X86_REG_DL:
        cpu->rdx = val; break;
    case X86_REG_RSI: case X86_REG_ESI: case X86_REG_SI: case X86_REG_SIL:
        cpu->rsi = val; break;
    case X86_REG_RDI: case X86_REG_EDI: case X86_REG_DI: case X86_REG_DIL:
        cpu->rdi = val; break;
    case X86_REG_RBP: case X86_REG_EBP: case X86_REG_BP: case X86_REG_BPL:
        cpu->rbp = val; break;
    case X86_REG_RSP: case X86_REG_ESP: case X86_REG_SP: case X86_REG_SPL:
        cpu->rsp = val; break;
    case X86_REG_R8:  case X86_REG_R8D:  case X86_REG_R8W:  case X86_REG_R8B:
        cpu->r8 = val; break;
    case X86_REG_R9:  case X86_REG_R9D:  case X86_REG_R9W:  case X86_REG_R9B:
        cpu->r9 = val; break;
    case X86_REG_R10: case X86_REG_R10D: case X86_REG_R10W: case X86_REG_R10B:
        cpu->r10 = val; break;
    case X86_REG_R11: case X86_REG_R11D: case X86_REG_R11W: case X86_REG_R11B:
        cpu->r11 = val; break;
    case X86_REG_R12: case X86_REG_R12D: case X86_REG_R12W: case X86_REG_R12B:
        cpu->r12 = val; break;
    case X86_REG_R13: case X86_REG_R13D: case X86_REG_R13W: case X86_REG_R13B:
        cpu->r13 = val; break;
    case X86_REG_R14: case X86_REG_R14D: case X86_REG_R14W: case X86_REG_R14B:
        cpu->r14 = val; break;
    case X86_REG_R15: case X86_REG_R15D: case X86_REG_R15W: case X86_REG_R15B:
        cpu->r15 = val; break;
    default:
        break;
    }
}
#endif // __x86_64__

static uint64_t compute_ea(const GumCpuContext *cpu, const mov_mem_info *info) {
    uint64_t ea = (uint64_t)info->disp;
    if (info->base_reg != X86_REG_INVALID)
        ea += read_reg(cpu, info->base_reg);
    if (info->index_reg != X86_REG_INVALID)
        ea += read_reg(cpu, info->index_reg) * info->scale;
    return ea;
}

// ---------------------------------------------------------------------------
// Per-instruction metadata passed through callout user_data
// ---------------------------------------------------------------------------

struct mov_callout_data {
    pgas_stalker_ctx *ctx;
    mov_mem_info info;
    // For loads: the destination register (to write result into)
    x86_reg dest_reg;
    // For stores: the source register (to read value from)
    x86_reg src_reg;
};

// We need to keep callout_data alive for the lifetime of the stalker.
// Use a simple growing vector protected by a mutex.
static std::vector<mov_callout_data *> g_callout_pool;
static std::mutex g_pool_mutex;

static mov_callout_data *alloc_callout_data() {
    auto *p = new mov_callout_data();
    std::lock_guard<std::mutex> lock(g_pool_mutex);
    g_callout_pool.push_back(p);
    return p;
}

static void free_callout_pool() {
    std::lock_guard<std::mutex> lock(g_pool_mutex);
    for (auto *p : g_callout_pool)
        delete p;
    g_callout_pool.clear();
}

// ---------------------------------------------------------------------------
// Callout: runs at each instrumented mov at runtime
// ---------------------------------------------------------------------------

static void mov_load_callout(GumCpuContext *cpu_context, gpointer user_data) {
    auto *cd = (mov_callout_data *)user_data;
    auto *ctx = cd->ctx;

    uint64_t ea = compute_ea(cpu_context, &cd->info);
    uint64_t base = ctx->config.pgas_base_addr;
    uint64_t end = base + ctx->config.pgas_region_size;

    if (ea < base || ea >= end) {
        // Not in CXL range - local passthrough, the original mov will execute
        __atomic_fetch_add(&ctx->stats.local_passthrough, 1, __ATOMIC_RELAXED);
        return;
    }

    // Route through CXLMemSim
    auto &hooker = pgas_cxlmemsim_hooker::instance();
    uint16_t node = hooker.addr_to_node(ea);

    if (node == ctx->config.local_node_id) {
        __atomic_fetch_add(&ctx->stats.local_passthrough, 1, __ATOMIC_RELAXED);
        return; // Local node - original mov is fine
    }

    // Remote load: fetch from CXLMemSim, write into destination register
    uint64_t val = 0;
    size_t sz = cd->info.access_size;
    if (sz > 8) sz = 8; // GP register max; XMM handled separately

    hooker.remote_read(node, ea, &val, sz);

    // Patch the destination register so when the original mov executes
    // (reading from a possibly-unmapped address), we've already got the value.
    // We write into the dest register and the Stalker will skip the original insn
    // if we didn't keep() it, OR we can write to dest and let the original
    // mov overwrite with garbage. So we must NOT keep the original insn for
    // remote loads - the transformer already skipped it.
    write_reg(cpu_context, cd->dest_reg, val);

    __atomic_fetch_add(&ctx->stats.remote_loads, 1, __ATOMIC_RELAXED);
}

static void mov_store_callout(GumCpuContext *cpu_context, gpointer user_data) {
    auto *cd = (mov_callout_data *)user_data;
    auto *ctx = cd->ctx;

    uint64_t ea = compute_ea(cpu_context, &cd->info);
    uint64_t base = ctx->config.pgas_base_addr;
    uint64_t end = base + ctx->config.pgas_region_size;

    if (ea < base || ea >= end) {
        __atomic_fetch_add(&ctx->stats.local_passthrough, 1, __ATOMIC_RELAXED);
        return;
    }

    auto &hooker = pgas_cxlmemsim_hooker::instance();
    uint16_t node = hooker.addr_to_node(ea);

    if (node == ctx->config.local_node_id) {
        __atomic_fetch_add(&ctx->stats.local_passthrough, 1, __ATOMIC_RELAXED);
        return;
    }

    // Read the value from the source register
    uint64_t val = read_reg(cpu_context, cd->src_reg);
    size_t sz = cd->info.access_size;
    if (sz > 8) sz = 8;

    hooker.remote_write(node, ea, &val, sz);

    // The transformer did NOT keep the original store instruction for remote,
    // so the write to the (possibly unmapped) local address is suppressed.
    __atomic_fetch_add(&ctx->stats.remote_stores, 1, __ATOMIC_RELAXED);
}

// ---------------------------------------------------------------------------
// Stalker transformer callback: scans each basic block
// ---------------------------------------------------------------------------

static void transform_block(GumStalkerIterator *iterator,
                            GumStalkerOutput *output, gpointer user_data) {
    auto *ctx = (pgas_stalker_ctx *)user_data;
    const cs_insn *insn;

    __atomic_fetch_add(&ctx->stats.blocks_transformed, 1, __ATOMIC_RELAXED);

    while (gum_stalker_iterator_next(iterator, &insn)) {
        __atomic_fetch_add(&ctx->stats.insns_scanned, 1, __ATOMIC_RELAXED);

        mov_mem_info info;
        bool dominated = analyze_mov(insn, &ctx->config, &info);

        if (!dominated) {
            // Not a mov with memory operand - keep as-is
            gum_stalker_iterator_keep(iterator);
            continue;
        }

        // Check: can we determine at JIT time that the displacement alone
        // puts us outside the CXL range? This is a fast-path optimization:
        // if disp is the only component (no base/index), we know the EA
        // at JIT time. If base/index are involved, we must defer to runtime.
        bool needs_runtime_check = (info.base_reg != X86_REG_INVALID ||
                                    info.index_reg != X86_REG_INVALID);

        if (!needs_runtime_check) {
            // EA is just the displacement (e.g., mov rax, [0x100000040])
            uint64_t ea = (uint64_t)info.disp;
            uint64_t base = ctx->config.pgas_base_addr;
            uint64_t end = base + ctx->config.pgas_region_size;
            if (ea < base || ea >= end) {
                // Statically outside CXL range - no instrumentation needed
                gum_stalker_iterator_keep(iterator);
                continue;
            }
        }

        // Allocate per-instruction metadata
        auto *cd = alloc_callout_data();
        cd->ctx = ctx;
        cd->info = info;

        const cs_x86 *x86 = &insn->detail->x86;

        if (info.is_load) {
            // Memory source -> register destination
            cd->dest_reg = (x86_reg)x86->operands[info.reg_op_idx].reg;
            cd->src_reg = X86_REG_INVALID;

            // Insert callout BEFORE, then DON'T keep the original insn.
            // The callout writes the loaded value into the dest register
            // if the EA is remote. If local, the callout is a no-op and
            // we need the original insn. Problem: we can't conditionally
            // keep at JIT time. Solution: always insert the callout, and
            // keep the original insn. For remote loads, the callout patches
            // the dest register; the original insn then overwrites with
            // the (possibly garbage) local memory, which is wrong.
            //
            // Correct approach: always replace the mov with a callout.
            // For local addresses, the callout performs the load itself.
            gum_stalker_iterator_put_callout(iterator, mov_load_callout, cd, NULL);
            // We keep the original insn for the LOCAL case (callout is no-op).
            // For REMOTE, the callout writes dest_reg; the original insn
            // reads from a local mirror that should be mapped (even if stale).
            // If the CXL range is not locally mapped, we MUST NOT keep it.
            //
            // Design decision: the CXL range [pgas_base, pgas_base+size)
            // must be mmap'd locally (PROT_READ|PROT_WRITE) as a shadow
            // region. Remote loads overwrite via callout; local loads hit
            // the shadow. This avoids SIGSEGV from unmapped addresses.
            gum_stalker_iterator_keep(iterator);

            __atomic_fetch_add(&ctx->stats.mov_loads_hooked, 1, __ATOMIC_RELAXED);

        } else if (info.is_store) {
            // Register source -> memory destination
            cd->src_reg = (x86_reg)x86->operands[info.reg_op_idx].reg;
            cd->dest_reg = X86_REG_INVALID;

            // Insert callout BEFORE the store. The callout sends to CXLMemSim
            // for remote addresses. We keep the original insn so the local
            // shadow is also updated (write-through to shadow + remote).
            gum_stalker_iterator_put_callout(iterator, mov_store_callout, cd, NULL);
            gum_stalker_iterator_keep(iterator);

            __atomic_fetch_add(&ctx->stats.mov_stores_hooked, 1, __ATOMIC_RELAXED);
        } else {
            // Shouldn't happen but be safe
            gum_stalker_iterator_keep(iterator);
        }
    }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

extern "C" {

pgas_stalker_ctx_t *pgas_stalker_init(const pgas_stalker_config_t *config) {
    auto *ctx = new pgas_stalker_ctx();
    memset(&ctx->stats, 0, sizeof(ctx->stats));
    ctx->config = *config;
    ctx->active = false;

    // Defaults
    if (!config->hook_mov && !config->hook_movzx &&
        !config->hook_movnti && !config->hook_rep_movs) {
        ctx->config.hook_mov = true;
        ctx->config.hook_movzx = true;
        ctx->config.hook_movnti = true;
    }

    ctx->stalker = gum_stalker_new();
    if (!ctx->stalker) {
        SPDLOG_ERROR("gum_stalker_new() failed - Stalker not supported?");
        delete ctx;
        return nullptr;
    }

    gum_stalker_set_trust_threshold(ctx->stalker, config->trust_threshold);

    // Create transformer from our callback
    ctx->transformer = gum_stalker_transformer_make_from_callback(
        transform_block, ctx, NULL);

    SPDLOG_INFO("PGAS Stalker initialized: base=0x{:x} size={} nodes={} trust={}",
                config->pgas_base_addr, config->pgas_region_size,
                config->num_nodes, config->trust_threshold);

    return ctx;
}

int pgas_stalker_follow_me(pgas_stalker_ctx_t *ctx) {
    if (!ctx || !ctx->stalker) return -1;

    tls_ctx = ctx;
    gum_stalker_follow_me(ctx->stalker, ctx->transformer, NULL);
    ctx->active = true;

    SPDLOG_INFO("Stalker following current thread");
    return 0;
}

int pgas_stalker_follow(pgas_stalker_ctx_t *ctx, GumThreadId thread_id) {
    if (!ctx || !ctx->stalker) return -1;

    gum_stalker_follow(ctx->stalker, thread_id, ctx->transformer, NULL);
    ctx->active = true;

    SPDLOG_INFO("Stalker following thread {}", thread_id);
    return 0;
}

void pgas_stalker_unfollow_me(pgas_stalker_ctx_t *ctx) {
    if (!ctx || !ctx->stalker) return;

    gum_stalker_unfollow_me(ctx->stalker);
    tls_ctx = nullptr;
    SPDLOG_INFO("Stalker unfollowed current thread");
}

void pgas_stalker_unfollow(pgas_stalker_ctx_t *ctx, GumThreadId thread_id) {
    if (!ctx || !ctx->stalker) return;

    gum_stalker_unfollow(ctx->stalker, thread_id);
    SPDLOG_INFO("Stalker unfollowed thread {}", thread_id);
}

void pgas_stalker_activate(pgas_stalker_ctx_t *ctx, const void *target) {
    if (!ctx || !ctx->stalker) return;
    gum_stalker_activate(ctx->stalker, target);
}

void pgas_stalker_deactivate(pgas_stalker_ctx_t *ctx) {
    if (!ctx || !ctx->stalker) return;
    gum_stalker_deactivate(ctx->stalker);
}

void pgas_stalker_exclude(pgas_stalker_ctx_t *ctx, uint64_t base, uint64_t size) {
    if (!ctx || !ctx->stalker) return;

    GumMemoryRange range;
    range.base_address = (GumAddress)base;
    range.size = (gsize)size;
    gum_stalker_exclude(ctx->stalker, &range);
}

void pgas_stalker_get_stats(pgas_stalker_ctx_t *ctx, pgas_stalker_stats_t *stats) {
    if (!ctx || !stats) return;
    *stats = ctx->stats;
}

void pgas_stalker_print_stats(pgas_stalker_ctx_t *ctx) {
    if (!ctx) return;

    printf("\n=== PGAS Stalker MOV Statistics ===\n");
    printf("Basic blocks transformed: %lu\n", ctx->stats.blocks_transformed);
    printf("Instructions scanned:     %lu\n", ctx->stats.insns_scanned);
    printf("MOV loads hooked (JIT):   %lu\n", ctx->stats.mov_loads_hooked);
    printf("MOV stores hooked (JIT):  %lu\n", ctx->stats.mov_stores_hooked);
    printf("Remote loads executed:    %lu\n", ctx->stats.remote_loads);
    printf("Remote stores executed:   %lu\n", ctx->stats.remote_stores);
    printf("Local passthrough:        %lu\n", ctx->stats.local_passthrough);
    printf("==================================\n\n");
}

void pgas_stalker_finalize(pgas_stalker_ctx_t *ctx) {
    if (!ctx) return;

    if (ctx->stalker) {
        gum_stalker_flush(ctx->stalker);
        gum_stalker_garbage_collect(ctx->stalker);
        g_object_unref(ctx->stalker);
    }
    if (ctx->transformer) {
        g_object_unref(ctx->transformer);
    }

    free_callout_pool();
    delete ctx;

    SPDLOG_INFO("PGAS Stalker finalized");
}

} // extern "C"
