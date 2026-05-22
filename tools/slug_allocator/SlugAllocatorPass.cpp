#include "llvm/ADT/SmallVector.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/DataLayout.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/PassManager.h"
#include "llvm/IR/Type.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Passes/PassPlugin.h"
#include "llvm/Support/Compiler.h"

#include <cstdint>
#include <iterator>
#include <utility>

using namespace llvm;

namespace
{

enum SlugAccessKind : uint32_t {
	SlugLoad = 0,
	SlugStore = 1,
	SlugAtomic = 2,
	SlugMemcpyRead = 3,
	SlugMemcpyWrite = 4,
	SlugMemset = 5,
};

struct RuntimeDecls {
	FunctionCallee bbEnter;
	FunctionCallee memAccess;
};

static uint32_t stableId(StringRef name)
{
	uint32_t hash = 2166136261u;
	for (unsigned char c : name) {
		hash ^= c;
		hash *= 16777619u;
	}
	return hash ? hash : 1u;
}

static bool isSlugRuntimeFunction(StringRef name)
{
	return name.starts_with("__slug_");
}

static uint64_t fixedStoreSize(const DataLayout &dl, Type *type)
{
	TypeSize size = dl.getTypeStoreSize(type);
	if (size.isScalable())
		return 0;
	return size.getFixedValue();
}

static RuntimeDecls getRuntimeDecls(Module &module)
{
	LLVMContext &ctx = module.getContext();
	Type *voidTy = Type::getVoidTy(ctx);
	Type *i32Ty = Type::getInt32Ty(ctx);
	Type *i64Ty = Type::getInt64Ty(ctx);
	Type *ptrTy = PointerType::get(ctx, 0);

	RuntimeDecls decls;
	decls.bbEnter = module.getOrInsertFunction(
		"__slug_bb_enter", voidTy, i32Ty, i32Ty, i32Ty, i32Ty, ptrTy);
	decls.memAccess = module.getOrInsertFunction(
		"__slug_mem_access", voidTy, ptrTy, i64Ty, i32Ty, i32Ty, i32Ty);
	return decls;
}

static Value *asI8Ptr(IRBuilder<> &builder, Value *ptr)
{
	if (ptr->getType()->isPointerTy())
		return ptr;
	return builder.CreateIntToPtr(ptr, builder.getPtrTy());
}

static void emitAccess(IRBuilder<> &builder, RuntimeDecls &decls, Value *addr,
		       Value *size, uint32_t kind, uint32_t functionId,
		       uint32_t basicBlockId)
{
	builder.CreateCall(decls.memAccess, { asI8Ptr(builder, addr), size,
					      builder.getInt32(kind),
					      builder.getInt32(functionId),
					      builder.getInt32(basicBlockId) });
}

static void emitAccess(IRBuilder<> &builder, RuntimeDecls &decls, Value *addr,
		       uint64_t size, uint32_t kind, uint32_t functionId,
		       uint32_t basicBlockId)
{
	if (size == 0)
		return;
	emitAccess(builder, decls, addr, builder.getInt64(size), kind,
		   functionId, basicBlockId);
}

static Value *memIntrinsicLength(IRBuilder<> &builder, Value *length)
{
	if (length->getType()->isIntegerTy(64))
		return length;
	if (length->getType()->isIntegerTy())
		return builder.CreateZExtOrTrunc(length, builder.getInt64Ty());
	return builder.getInt64(0);
}

static IRBuilder<> builderAfter(Instruction *inst)
{
	return IRBuilder<>(inst->getParent(), std::next(inst->getIterator()));
}

class SlugAllocatorPass : public PassInfoMixin<SlugAllocatorPass> {
    public:
	static bool isRequired()
	{
		return true;
	}

	PreservedAnalyses run(Function &function, FunctionAnalysisManager &)
	{
		if (function.isDeclaration() || function.empty() ||
		    isSlugRuntimeFunction(function.getName())) {
			return PreservedAnalyses::all();
		}

		Module &module = *function.getParent();
		const DataLayout &dl = module.getDataLayout();
		RuntimeDecls decls = getRuntimeDecls(module);
		uint32_t functionId = stableId(function.getName());
		bool changed = false;

		SmallVector<Instruction *, 64> memoryInstructions;
		for (Instruction &inst : instructions(function)) {
			if (isa<LoadInst, StoreInst, AtomicRMWInst,
				AtomicCmpXchgInst, MemIntrinsic>(&inst)) {
				memoryInstructions.push_back(&inst);
			}
		}

		uint32_t bbIndex = 0;
		for (BasicBlock &bb : function) {
			uint32_t basicBlockId = stableId(function.getName()) ^
						stableId(bb.getName()) ^
						(0x9e3779b9u + bbIndex);
			uint32_t loadCount = 0;
			uint32_t storeCount = 0;

			for (Instruction &inst : bb) {
				if (isa<LoadInst>(&inst))
					loadCount++;
				else if (isa<StoreInst>(&inst))
					storeCount++;
				else if (isa<AtomicRMWInst, AtomicCmpXchgInst>(
						 &inst)) {
					loadCount++;
					storeCount++;
				} else if (auto *memcpyInst =
						   dyn_cast<MemTransferInst>(
							   &inst)) {
					(void)memcpyInst;
					loadCount++;
					storeCount++;
				} else if (isa<MemSetInst>(&inst)) {
					storeCount++;
				}
			}

			BasicBlock::iterator insertIt =
				bb.getFirstInsertionPt();
			if (insertIt != bb.end()) {
				IRBuilder<> builder(&*insertIt);
				Value *name = builder.CreateGlobalString(
					function.getName(), ".slug.fn");
				builder.CreateCall(
					decls.bbEnter,
					{ builder.getInt32(functionId),
					  builder.getInt32(basicBlockId),
					  builder.getInt32(loadCount),
					  builder.getInt32(storeCount), name });
				changed = true;
			}
			bbIndex++;
		}

		for (Instruction *inst : memoryInstructions) {
			BasicBlock *bb = inst->getParent();
			uint32_t basicBlockId = stableId(function.getName()) ^
						stableId(bb->getName());
			uint32_t bbOrdinal = 0;
			for (BasicBlock &candidate : function) {
				if (&candidate == bb)
					break;
				bbOrdinal++;
			}
			basicBlockId ^= (0x9e3779b9u + bbOrdinal);

			if (auto *load = dyn_cast<LoadInst>(inst)) {
				IRBuilder<> builder(load);
				emitAccess(builder, decls,
					   load->getPointerOperand(),
					   fixedStoreSize(dl, load->getType()),
					   SlugLoad, functionId, basicBlockId);
				changed = true;
				continue;
			}

			if (auto *store = dyn_cast<StoreInst>(inst)) {
				IRBuilder<> builder = builderAfter(store);
				emitAccess(builder, decls,
					   store->getPointerOperand(),
					   fixedStoreSize(
						   dl, store->getValueOperand()
							       ->getType()),
					   SlugStore, functionId, basicBlockId);
				changed = true;
				continue;
			}

			if (auto *rmw = dyn_cast<AtomicRMWInst>(inst)) {
				IRBuilder<> builder = builderAfter(rmw);
				emitAccess(
					builder, decls,
					rmw->getPointerOperand(),
					fixedStoreSize(dl, rmw->getValOperand()
								   ->getType()),
					SlugAtomic, functionId, basicBlockId);
				changed = true;
				continue;
			}

			if (auto *cmpxchg = dyn_cast<AtomicCmpXchgInst>(inst)) {
				IRBuilder<> builder = builderAfter(cmpxchg);
				emitAccess(
					builder, decls,
					cmpxchg->getPointerOperand(),
					fixedStoreSize(
						dl, cmpxchg->getCompareOperand()
							    ->getType()),
					SlugAtomic, functionId, basicBlockId);
				changed = true;
				continue;
			}

			if (auto *transfer = dyn_cast<MemTransferInst>(inst)) {
				IRBuilder<> builder(transfer);
				Value *len = memIntrinsicLength(
					builder, transfer->getLength());
				emitAccess(builder, decls,
					   transfer->getRawSource(), len,
					   SlugMemcpyRead, functionId,
					   basicBlockId);
				IRBuilder<> afterBuilder =
					builderAfter(transfer);
				emitAccess(afterBuilder, decls,
					   transfer->getRawDest(), len,
					   SlugMemcpyWrite, functionId,
					   basicBlockId);
				changed = true;
				continue;
			}

			if (auto *set = dyn_cast<MemSetInst>(inst)) {
				IRBuilder<> builder(set);
				Value *len = memIntrinsicLength(
					builder, set->getLength());
				IRBuilder<> afterBuilder = builderAfter(set);
				emitAccess(afterBuilder, decls,
					   set->getRawDest(), len, SlugMemset,
					   functionId, basicBlockId);
				changed = true;
				continue;
			}
		}

		return changed ? PreservedAnalyses::none() :
				 PreservedAnalyses::all();
	}
};

} // namespace

extern "C" LLVM_ATTRIBUTE_WEAK PassPluginLibraryInfo llvmGetPassPluginInfo()
{
	return {
		LLVM_PLUGIN_API_VERSION, "SlugAllocator", LLVM_VERSION_STRING,
		[](PassBuilder &passBuilder) {
			passBuilder.registerPipelineStartEPCallback(
				[](ModulePassManager &modulePM,
				   OptimizationLevel) {
					FunctionPassManager functionPM;
					functionPM.addPass(SlugAllocatorPass());
					modulePM.addPass(
						createModuleToFunctionPassAdaptor(
							std::move(functionPM)));
				});
			passBuilder.registerPipelineParsingCallback(
				[](StringRef name,
				   FunctionPassManager &functionPM,
				   ArrayRef<PassBuilder::PipelineElement>) {
					if (name == "slug-allocator") {
						functionPM.addPass(
							SlugAllocatorPass());
						return true;
					}
					return false;
				});
		}
	};
}
