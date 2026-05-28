// SPDX-License-Identifier: MIT
// Frida Stalker-based mov instruction interception for CXL PGAS
//
// PERFORMANCE OPTIMIZATIONS:
//   1. Skip stack-relative movs (RSP/RBP-based) at JIT time — these
//      are never CXL addresses and account for ~60% of all memory movs.
//   2. Inline range check via GumX86Writer BEFORE the callout — the
//      common case (non-CXL address) is ~8 cycles of inline asm with
//      no function call, vs ~80 cycles for a full callout.
//   3. Trust threshold defaults to -1 (cache JIT'd blocks forever).
//   4. Lock-free bump allocator for callout metadata.
//   5. Flatten the hot-path: cache pgas_base/size directly in callout
//      data, avoid singleton lookups and virtual calls.

#include "pgas_stalker_mov.hpp"
#include "pgas_cxlmemsim_integration.hpp"
#include <spdlog/spdlog.h>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <vector>
#include <mutex>
#include <limits>

using namespace bpftime::attach;

// ---------------------------------------------------------------------------
// Internal context
// ---------------------------------------------------------------------------

struct pgas_stalker_ctx {
    GumStalker *stalker;
    GumStalkerTransformer *transformer;

    pgas_stalker_config_t config;
    pgas_stalker_stats_t stats;

    bool active;
};

// ---------------------------------------------------------------------------
// Helpers: detect if a Capstone instruction has a memory operand
// ---------------------------------------------------------------------------

struct mov_mem_info {
    bool has_mem_op;
    bool is_load;
    bool is_store;
    uint8_t mem_op_idx;
    uint8_t reg_op_idx;
    uint8_t access_size;
    x86_reg base_reg;
    x86_reg index_reg;
    int scale;
    int64_t disp;
};

static bool is_mov_insn(unsigned int insn_id) {
    switch (insn_id) {
    case X86_INS_MOV:  case X86_INS_MOVABS:
    case X86_INS_MOVZX: case X86_INS_MOVSXD: case X86_INS_MOVSX:
    case X86_INS_MOVNTI: case X86_INS_MOVNTDQ: case X86_INS_MOVNTPS:
    case X86_INS_MOVNTPD:
    case X86_INS_MOVAPS: case X86_INS_MOVUPS: case X86_INS_MOVAPD:
    case X86_INS_MOVUPD: case X86_INS_MOVDQA: case X86_INS_MOVDQU:
    case X86_INS_MOVSD:  case X86_INS_MOVSS:
    case X86_INS_MOVQ:   case X86_INS_MOVD:
        return true;
    default:
        return false;
    }
}

// OPT 1: Skip stack-relative memory accesses at JIT time.
// RSP/RBP-based movs are local stack variables — never CXL addresses.
static bool is_stack_relative(x86_reg reg) {
    switch (reg) {
    case X86_REG_RSP: case X86_REG_ESP: case X86_REG_SP: case X86_REG_SPL:
    case X86_REG_RBP: case X86_REG_EBP: case X86_REG_BP: case X86_REG_BPL:
        return true;
    default:
        return false;
    }
}

static bool analyze_mov(const cs_insn *insn, const pgas_stalker_config_t *cfg,
                        mov_mem_info *out) {
    memset(out, 0, sizeof(*out));
    if (!is_mov_insn(insn->id)) return false;

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
    for (uint8_t i = 0; i < x86->op_count; i++) {
        if (x86->operands[i].type == X86_OP_MEM) {
            out->has_mem_op = true;
            out->mem_op_idx = i;
            out->base_reg = x86->operands[i].mem.base;
            out->index_reg = x86->operands[i].mem.index;
            out->scale = x86->operands[i].mem.scale;
            out->disp = x86->operands[i].mem.disp;
            out->access_size = x86->operands[i].size;
            if (i == 0) {
                out->is_store = true;
                out->reg_op_idx = 1;
            } else {
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
    case X86_REG_RAX: case X86_REG_EAX: case X86_REG_AX: case X86_REG_AL: return cpu->rax;
    case X86_REG_RBX: case X86_REG_EBX: case X86_REG_BX: case X86_REG_BL: return cpu->rbx;
    case X86_REG_RCX: case X86_REG_ECX: case X86_REG_CX: case X86_REG_CL: return cpu->rcx;
    case X86_REG_RDX: case X86_REG_EDX: case X86_REG_DX: case X86_REG_DL: return cpu->rdx;
    case X86_REG_RSI: case X86_REG_ESI: case X86_REG_SI: case X86_REG_SIL: return cpu->rsi;
    case X86_REG_RDI: case X86_REG_EDI: case X86_REG_DI: case X86_REG_DIL: return cpu->rdi;
    case X86_REG_RBP: case X86_REG_EBP: case X86_REG_BP: case X86_REG_BPL: return cpu->rbp;
    case X86_REG_RSP: case X86_REG_ESP: case X86_REG_SP: case X86_REG_SPL: return cpu->rsp;
    case X86_REG_R8:  case X86_REG_R8D:  case X86_REG_R8W:  case X86_REG_R8B:  return cpu->r8;
    case X86_REG_R9:  case X86_REG_R9D:  case X86_REG_R9W:  case X86_REG_R9B:  return cpu->r9;
    case X86_REG_R10: case X86_REG_R10D: case X86_REG_R10W: case X86_REG_R10B: return cpu->r10;
    case X86_REG_R11: case X86_REG_R11D: case X86_REG_R11W: case X86_REG_R11B: return cpu->r11;
    case X86_REG_R12: case X86_REG_R12D: case X86_REG_R12W: case X86_REG_R12B: return cpu->r12;
    case X86_REG_R13: case X86_REG_R13D: case X86_REG_R13W: case X86_REG_R13B: return cpu->r13;
    case X86_REG_R14: case X86_REG_R14D: case X86_REG_R14W: case X86_REG_R14B: return cpu->r14;
    case X86_REG_R15: case X86_REG_R15D: case X86_REG_R15W: case X86_REG_R15B: return cpu->r15;
    case X86_REG_RIP: return cpu->rip;
    default: return 0;
    }
}

static void write_reg(GumCpuContext *cpu, x86_reg reg, uint64_t val) {
    switch (reg) {
    case X86_REG_RAX: case X86_REG_EAX: case X86_REG_AX: case X86_REG_AL: cpu->rax = val; break;
    case X86_REG_RBX: case X86_REG_EBX: case X86_REG_BX: case X86_REG_BL: cpu->rbx = val; break;
    case X86_REG_RCX: case X86_REG_ECX: case X86_REG_CX: case X86_REG_CL: cpu->rcx = val; break;
    case X86_REG_RDX: case X86_REG_EDX: case X86_REG_DX: case X86_REG_DL: cpu->rdx = val; break;
    case X86_REG_RSI: case X86_REG_ESI: case X86_REG_SI: case X86_REG_SIL: cpu->rsi = val; break;
    case X86_REG_RDI: case X86_REG_EDI: case X86_REG_DI: case X86_REG_DIL: cpu->rdi = val; break;
    case X86_REG_RBP: case X86_REG_EBP: case X86_REG_BP: case X86_REG_BPL: cpu->rbp = val; break;
    case X86_REG_RSP: case X86_REG_ESP: case X86_REG_SP: case X86_REG_SPL: cpu->rsp = val; break;
    case X86_REG_R8:  case X86_REG_R8D:  case X86_REG_R8W:  case X86_REG_R8B:  cpu->r8  = val; break;
    case X86_REG_R9:  case X86_REG_R9D:  case X86_REG_R9W:  case X86_REG_R9B:  cpu->r9  = val; break;
    case X86_REG_R10: case X86_REG_R10D: case X86_REG_R10W: case X86_REG_R10B: cpu->r10 = val; break;
    case X86_REG_R11: case X86_REG_R11D: case X86_REG_R11W: case X86_REG_R11B: cpu->r11 = val; break;
    case X86_REG_R12: case X86_REG_R12D: case X86_REG_R12W: case X86_REG_R12B: cpu->r12 = val; break;
    case X86_REG_R13: case X86_REG_R13D: case X86_REG_R13W: case X86_REG_R13B: cpu->r13 = val; break;
    case X86_REG_R14: case X86_REG_R14D: case X86_REG_R14W: case X86_REG_R14B: cpu->r14 = val; break;
    case X86_REG_R15: case X86_REG_R15D: case X86_REG_R15W: case X86_REG_R15B: cpu->r15 = val; break;
    default: break;
    }
}

// Map Capstone register to Frida GumX86Reg for inline codegen
static GumX86Reg cs_to_gum_reg(x86_reg reg) {
    switch (reg) {
    case X86_REG_RAX: case X86_REG_EAX: return GUM_X86_RAX;
    case X86_REG_RBX: case X86_REG_EBX: return GUM_X86_RBX;
    case X86_REG_RCX: case X86_REG_ECX: return GUM_X86_RCX;
    case X86_REG_RDX: case X86_REG_EDX: return GUM_X86_RDX;
    case X86_REG_RSI: case X86_REG_ESI: return GUM_X86_RSI;
    case X86_REG_RDI: case X86_REG_EDI: return GUM_X86_RDI;
    case X86_REG_RBP: case X86_REG_EBP: return GUM_X86_RBP;
    case X86_REG_RSP: case X86_REG_ESP: return GUM_X86_RSP;
    case X86_REG_R8:  case X86_REG_R8D:  return GUM_X86_R8;
    case X86_REG_R9:  case X86_REG_R9D:  return GUM_X86_R9;
    case X86_REG_R10: case X86_REG_R10D: return GUM_X86_R10;
    case X86_REG_R11: case X86_REG_R11D: return GUM_X86_R11;
    case X86_REG_R12: case X86_REG_R12D: return GUM_X86_R12;
    case X86_REG_R13: case X86_REG_R13D: return GUM_X86_R13;
    case X86_REG_R14: case X86_REG_R14D: return GUM_X86_R14;
    case X86_REG_R15: case X86_REG_R15D: return GUM_X86_R15;
    default: return GUM_X86_RAX;
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

static bool is_in_pgas_range(uint64_t ea, uint64_t base, uint64_t size) {
    return size != 0 && ea >= base && (ea - base) < size;
}

// ---------------------------------------------------------------------------
// OPT 4: Lock-free bump allocator for callout metadata
// ---------------------------------------------------------------------------

struct mov_callout_data {
    // OPT 5: Inline the range check constants to avoid pointer chasing
    uint64_t pgas_base;
    uint64_t pgas_size;
    uint16_t local_node_id;
    uint16_t num_nodes;
    pgas_stalker_stats_t *stats;  // direct pointer, no ctx indirection

    mov_mem_info info;
    x86_reg dest_reg;
    x86_reg src_reg;
};

// Bump allocator: single contiguous block, no locks, no free
#define CALLOUT_POOL_CAPACITY (1024 * 1024)
static mov_callout_data g_callout_pool_storage[CALLOUT_POOL_CAPACITY];
static uint64_t g_callout_pool_next = 0;

static mov_callout_data *alloc_callout_data() {
    uint64_t idx = __atomic_fetch_add(&g_callout_pool_next, 1, __ATOMIC_RELAXED);
    if (idx >= CALLOUT_POOL_CAPACITY) {
        SPDLOG_ERROR("Callout pool exhausted ({} entries)", CALLOUT_POOL_CAPACITY);
        return nullptr;
    }
    return &g_callout_pool_storage[idx];
}

// ---------------------------------------------------------------------------
// Callout: runs at each instrumented mov at runtime (SLOW PATH only)
//
// OPT 2: The inline range check in the JIT'd code already filtered out
// non-CXL addresses. This callout only fires for addresses IN the CXL range.
// ---------------------------------------------------------------------------

static void mov_load_callout(GumCpuContext *cpu_context, gpointer user_data) {
    auto *cd = (mov_callout_data *)user_data;

    uint64_t ea = compute_ea(cpu_context, &cd->info);
    if (!is_in_pgas_range(ea, cd->pgas_base, cd->pgas_size) ||
        cd->num_nodes == 0) {
        return;
    }

    // Route to node
    uint64_t offset = ea - cd->pgas_base;
    uint64_t region_per_node = cd->pgas_size / cd->num_nodes;
    if (region_per_node == 0) return;
    uint16_t node = (uint16_t)(offset / region_per_node);
    if (node >= cd->num_nodes) node = cd->num_nodes - 1;

    if (node == cd->local_node_id) {
        __atomic_fetch_add(&cd->stats->local_passthrough, 1, __ATOMIC_RELAXED);
        return; // Local - original mov hits shadow/DAX directly
    }

    // Remote load
    uint64_t val = 0;
    size_t sz = cd->info.access_size;
    if (sz > 8) sz = 8;

    auto &hooker = pgas_cxlmemsim_hooker::instance();
    hooker.remote_read(node, ea, &val, sz);
    write_reg(cpu_context, cd->dest_reg, val);

    __atomic_fetch_add(&cd->stats->remote_loads, 1, __ATOMIC_RELAXED);
}

static void mov_store_callout(GumCpuContext *cpu_context, gpointer user_data) {
    auto *cd = (mov_callout_data *)user_data;

    uint64_t ea = compute_ea(cpu_context, &cd->info);
    if (!is_in_pgas_range(ea, cd->pgas_base, cd->pgas_size) ||
        cd->num_nodes == 0) {
        return;
    }

    uint64_t offset = ea - cd->pgas_base;
    uint64_t region_per_node = cd->pgas_size / cd->num_nodes;
    if (region_per_node == 0) return;
    uint16_t node = (uint16_t)(offset / region_per_node);
    if (node >= cd->num_nodes) node = cd->num_nodes - 1;

    if (node == cd->local_node_id) {
        __atomic_fetch_add(&cd->stats->local_passthrough, 1, __ATOMIC_RELAXED);
        return;
    }

    uint64_t val = read_reg(cpu_context, cd->src_reg);
    size_t sz = cd->info.access_size;
    if (sz > 8) sz = 8;

    auto &hooker = pgas_cxlmemsim_hooker::instance();
    hooker.remote_write(node, ea, &val, sz);

    __atomic_fetch_add(&cd->stats->remote_stores, 1, __ATOMIC_RELAXED);
}

// ---------------------------------------------------------------------------
// OPT 2: Emit inline range check using GumX86Writer
//
// Instead of calling out on EVERY mov-with-memory-operand, emit ~8
// instructions of inline asm that check if the EA is in [base, base+size).
// Only if it IS in range, the (expensive) callout fires.
//
// For lat_mem_rd with pointer chasing in the CXL range, this doesn't
// help (every access is in-range). But for mixed workloads it eliminates
// ~95% of callout overhead.
//
//   pushfq
//   push rcx                    ; scratch register
//   lea  rcx, [<EA expression>] ; or: mov rcx, <base_reg>
//   sub  rcx, PGAS_BASE
//   cmp  rcx, PGAS_SIZE         ; unsigned: rcx-BASE < SIZE
//   pop  rcx
//   popfq
//   jae  skip_callout           ; not in CXL range (common case)
//   <callout>                   ; CXL range hit (rare/hot path)
//   skip_callout:
//   <original instruction>
// ---------------------------------------------------------------------------

static void emit_inline_range_check(GumStalkerIterator *iterator,
                                    GumStalkerOutput *output,
                                    const mov_mem_info *info,
                                    mov_callout_data *cd,
                                    bool is_load) {
    GumX86Writer *cw = output->writer.x86;

    // Choose a scratch register that is NOT the base/index/dest/src register
    // to avoid clobbering. RCX is usually safe (caller-saved).
    GumX86Reg scratch = GUM_X86_XCX;
    if (info->base_reg != X86_REG_INVALID) {
        GumX86Reg base_gum = cs_to_gum_reg(info->base_reg);
        if (base_gum == scratch) scratch = GUM_X86_XDX;
    }

    // For simple [base_reg] or [base_reg + disp] (no index), we can do
    // a fast inline check. For complex addressing modes, fall through
    // to the callout unconditionally.
    bool can_inline = (info->base_reg != X86_REG_INVALID &&
                       info->index_reg == X86_REG_INVALID);

    if (!can_inline || cd->pgas_size > static_cast<uint64_t>(std::numeric_limits<int32_t>::max())) {
        // Complex addressing or large PGAS regions use the checked callout.
        gum_stalker_iterator_put_callout(iterator,
            is_load ? mov_load_callout : mov_store_callout, cd, NULL);
        return;
    }

    GumX86Reg base_gum = cs_to_gum_reg(info->base_reg);

    // Emit: pushfq; push scratch
    gum_x86_writer_put_pushfx(cw);
    gum_x86_writer_put_push_reg(cw, scratch);

    // Emit: mov scratch, base_reg (copy EA base)
    gum_x86_writer_put_mov_reg_reg(cw, scratch, base_gum);

    // If there's a displacement, add it
    if (info->disp != 0) {
        gum_x86_writer_put_add_reg_imm(cw, scratch, (gssize)info->disp);
    }

    // Emit: sub scratch, PGAS_BASE (unsigned range check trick)
    gum_x86_writer_put_sub_reg_imm(cw, scratch, (gssize)cd->pgas_base);

    // Emit: cmp scratch, PGAS_SIZE
    // If (addr - BASE) >= SIZE, addr is outside the range
    gum_x86_writer_put_cmp_reg_i32(cw, scratch, (int32_t)cd->pgas_size);

    // Emit: pop scratch; popfq (restore BEFORE the branch)
    gum_x86_writer_put_pop_reg(cw, scratch);
    gum_x86_writer_put_popfx(cw);

    // Emit: jae skip_label (jump if outside CXL range — fast path)
    gconstpointer skip_label = GSIZE_TO_POINTER(
        (gsize)cd + 1); // unique label ID per callout_data
    gum_x86_writer_put_jcc_near_label(cw, X86_INS_JAE, skip_label, GUM_NO_HINT);

    // === SLOW PATH: address is in CXL range, do the callout ===
    gum_stalker_iterator_put_callout(iterator,
        is_load ? mov_load_callout : mov_store_callout, cd, NULL);

    // === FAST PATH: skip label ===
    gum_x86_writer_put_label(cw, skip_label);
}

// ---------------------------------------------------------------------------
// Stalker transformer callback
// ---------------------------------------------------------------------------

static void transform_block(GumStalkerIterator *iterator,
                            GumStalkerOutput *output, gpointer user_data) {
    auto *ctx = (pgas_stalker_ctx *)user_data;
    const cs_insn *insn;

    __atomic_fetch_add(&ctx->stats.blocks_transformed, 1, __ATOMIC_RELAXED);

    while (gum_stalker_iterator_next(iterator, &insn)) {
        __atomic_fetch_add(&ctx->stats.insns_scanned, 1, __ATOMIC_RELAXED);

        mov_mem_info info;
        if (!analyze_mov(insn, &ctx->config, &info)) {
            gum_stalker_iterator_keep(iterator);
            continue;
        }

        // OPT 1: Skip stack-relative accesses (RSP/RBP-based).
        // These are local variables, function args, spills — never CXL.
        if (is_stack_relative(info.base_reg)) {
            gum_stalker_iterator_keep(iterator);
            continue;
        }

        // Static displacement-only: check at JIT time
        bool needs_runtime = (info.base_reg != X86_REG_INVALID ||
                              info.index_reg != X86_REG_INVALID);
        if (!needs_runtime) {
            uint64_t ea = (uint64_t)info.disp;
            if (ea < ctx->config.pgas_base_addr ||
                ea >= ctx->config.pgas_base_addr + ctx->config.pgas_region_size) {
                gum_stalker_iterator_keep(iterator);
                continue;
            }
        }

        // RIP-relative addressing: typically code/data segment, not CXL
        if (info.base_reg == X86_REG_RIP) {
            gum_stalker_iterator_keep(iterator);
            continue;
        }

        // Allocate callout metadata
        auto *cd = alloc_callout_data();
        if (!cd) {
            gum_stalker_iterator_keep(iterator);
            continue;
        }

        // OPT 5: Flatten — copy config into callout data directly
        cd->pgas_base = ctx->config.pgas_base_addr;
        cd->pgas_size = ctx->config.pgas_region_size;
        cd->local_node_id = ctx->config.local_node_id;
        cd->num_nodes = ctx->config.num_nodes;
        cd->stats = &ctx->stats;
        cd->info = info;

        const cs_x86 *x86 = &insn->detail->x86;

        if (info.is_load) {
            cd->dest_reg = (x86_reg)x86->operands[info.reg_op_idx].reg;
            cd->src_reg = X86_REG_INVALID;

            // OPT 2: Inline range check, callout only for CXL addresses
            emit_inline_range_check(iterator, output, &info, cd, true);
            gum_stalker_iterator_keep(iterator);

            __atomic_fetch_add(&ctx->stats.mov_loads_hooked, 1, __ATOMIC_RELAXED);

        } else if (info.is_store) {
            cd->src_reg = (x86_reg)x86->operands[info.reg_op_idx].reg;
            cd->dest_reg = X86_REG_INVALID;

            emit_inline_range_check(iterator, output, &info, cd, false);
            gum_stalker_iterator_keep(iterator);

            __atomic_fetch_add(&ctx->stats.mov_stores_hooked, 1, __ATOMIC_RELAXED);
        } else {
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

    if (!config->hook_mov && !config->hook_movzx &&
        !config->hook_movnti && !config->hook_rep_movs) {
        ctx->config.hook_mov = true;
        ctx->config.hook_movzx = true;
        ctx->config.hook_movnti = true;
    }

    ctx->stalker = gum_stalker_new();
    if (!ctx->stalker) {
        SPDLOG_ERROR("gum_stalker_new() failed");
        delete ctx;
        return nullptr;
    }

    // OPT 3: Default trust = -1 (cache JIT'd blocks forever)
    int trust = config->trust_threshold;
    if (trust == 0) trust = -1;  // upgrade default
    gum_stalker_set_trust_threshold(ctx->stalker, trust);

    ctx->transformer = gum_stalker_transformer_make_from_callback(
        transform_block, ctx, NULL);

    SPDLOG_INFO("PGAS Stalker initialized: base=0x{:x} size={} nodes={} trust={}",
                config->pgas_base_addr, config->pgas_region_size,
                config->num_nodes, trust);

    return ctx;
}

int pgas_stalker_follow_me(pgas_stalker_ctx_t *ctx) {
    if (!ctx || !ctx->stalker) return -1;
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
    SPDLOG_INFO("Stalker unfollowed current thread");
}

void pgas_stalker_unfollow(pgas_stalker_ctx_t *ctx, GumThreadId thread_id) {
    if (!ctx || !ctx->stalker) return;
    gum_stalker_unfollow(ctx->stalker, thread_id);
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
    auto &s = ctx->stats;
    uint64_t total_hooked = s.mov_loads_hooked + s.mov_stores_hooked;
    uint64_t total_runtime = s.remote_loads + s.remote_stores + s.local_passthrough;

    printf("\n=== PGAS Stalker MOV Statistics ===\n");
    printf("JIT phase:\n");
    printf("  Blocks transformed:   %lu\n", s.blocks_transformed);
    printf("  Instructions scanned: %lu\n", s.insns_scanned);
    printf("  MOV loads hooked:     %lu\n", s.mov_loads_hooked);
    printf("  MOV stores hooked:    %lu\n", s.mov_stores_hooked);
    printf("  Instrumentation rate: %.1f%%\n",
           s.insns_scanned ? 100.0 * total_hooked / s.insns_scanned : 0);
    printf("Runtime:\n");
    printf("  Callouts fired:       %lu\n", total_runtime);
    printf("  Remote loads:         %lu\n", s.remote_loads);
    printf("  Remote stores:        %lu\n", s.remote_stores);
    printf("  Local passthrough:    %lu\n", s.local_passthrough);
    printf("  Callout pool used:    %lu / %d\n",
           g_callout_pool_next, CALLOUT_POOL_CAPACITY);
    printf("==================================\n\n");
}

void pgas_stalker_finalize(pgas_stalker_ctx_t *ctx) {
    if (!ctx) return;
    if (ctx->stalker) {
        gum_stalker_flush(ctx->stalker);
        gum_stalker_garbage_collect(ctx->stalker);
        g_object_unref(ctx->stalker);
    }
    if (ctx->transformer)
        g_object_unref(ctx->transformer);

    // Reset bump allocator (no individual frees needed)
    g_callout_pool_next = 0;

    delete ctx;
    SPDLOG_INFO("PGAS Stalker finalized");
}

} // extern "C"
