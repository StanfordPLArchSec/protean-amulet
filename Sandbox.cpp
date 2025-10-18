#include "Pass.h"

#include <llvm/IR/InstIterator.h>
#include <llvm/ADT/SCCIterator.h>
#include <llvm/IR/IntrinsicsX86.h>

using namespace llvm;

class SandboxPass : public PassInfoMixin<SandboxPass> {
public:
  PreservedAnalyses run(Module &M, ModuleAnalysisManager &MAM) {
    for (Function &F : M) {
      if (!F.isDeclaration()) {
        runOnFunction(F);
      }
    }
    return PreservedAnalyses::none();
  }

private:
  std::pair<BasicBlock *, BasicBlock *> findCriticalEdge(ArrayRef<BasicBlock *> SCC) {
    for (BasicBlock *B : SCC)
      for (BasicBlock *SuccB : llvm::successors(B))
        if (!llvm::is_contained(SCC, SuccB))
          return {B, SuccB};
    report_fatal_error("impossible!");
  }

  bool isCyclicSCC(ArrayRef<BasicBlock *> SCC) {
    if (SCC.size() > 1)
      return true;
    BasicBlock *B = SCC[0];

    // Is it its own successor?
    for (BasicBlock *SuccB : llvm::successors(B))
      if (SuccB == B)
        return true;

    return false;
  }

  void removeCyclesInSCC(ArrayRef<BasicBlock *> SCC) {
    auto [SrcB, DstB] = findCriticalEdge(SCC);
    // Remove the terminator and replace it with a direct unconditional branch to DstB.
    SrcB->getTerminator()->eraseFromParent();
    IRBuilder<> IRB(SrcB);
    IRB.CreateBr(DstB);
  }
  
  void removeCyclesInFunction(Function &F) {
  restart:
    for (auto scc_it = scc_begin(&F); scc_it != scc_end(&F); ++scc_it) {
      const auto &scc = *scc_it;
      if (isCyclicSCC(scc)) {
        removeCyclesInSCC(scc);
        goto restart; // NOTE: Need to restart because we invalidate the CFG.
      }
    }
  }

  Use *getPointerUse(Instruction &I) {
    assert(I.mayReadOrWriteMemory());
    Use *U = nullptr;
    if (auto *LI = dyn_cast<LoadInst>(&I)) {
      U = &LI->getOperandUse(0);
      assert(U->get() == LI->getPointerOperand());
    } else if (auto *SI = dyn_cast<StoreInst>(&I)) {
      U = &SI->getOperandUse(1);
      assert(U->get() == SI->getPointerOperand());
    }
    if (!U)
      llvm::report_fatal_error("unhandled instruction in getPointerUseImpl");
    return U;
  }

  Align getAlign(Instruction &I) {
    assert(I.mayReadOrWriteMemory());
    if (auto *LI = dyn_cast<LoadInst>(&I)) {
      return LI->getAlign();
    } else if (auto *SI = dyn_cast<StoreInst>(&I)) {
      return SI->getAlign();
    }
    llvm::report_fatal_error("unhandled instruction in getAlign");
  }

  void maskAccess(Instruction &I, Value *SandboxBase, Value *SandboxMask) {
    // Get the pointer operand.
    Use *PtrU = getPointerUse(I);
    Align A = getAlign(I);
    Value *Ptr = PtrU->get();
    IRBuilder<> IRB(&I);
    Ptr = IRB.CreatePtrToInt(Ptr, IRB.getInt64Ty());
#if 0
    Ptr = IRB.CreateAnd(Ptr, IRB.getInt64(~(A.value() - 1))); // Align the access.
#endif
    Ptr = IRB.CreateAnd(Ptr, SandboxMask);
    Ptr = IRB.CreateAdd(Ptr, SandboxBase); // TODO: Could be GEP?
    Ptr = IRB.CreateIntToPtr(Ptr, IRB.getPtrTy());
    PtrU->set(Ptr);
  }

  void maskAccesses(Function &F, Value *SandboxBase, Value *SandboxMask) {
    for (Instruction &I : llvm::make_early_inc_range(llvm::instructions(F)))
      if (I.mayReadOrWriteMemory())
        maskAccess(I, SandboxBase, SandboxMask);
  }

  void maskDivision(Function &F) {
    for (Instruction &I : llvm::instructions(F)) {
      if (I.isIntDivRem()) {
        auto *BinOp = cast<BinaryOperator>(&I);
        Use &DenomUse = BinOp->getOperandUse(1);
        Value *Denom = DenomUse.get();
        IRBuilder<> IRB(&I);
        Value *IsZero = IRB.CreateICmp(CmpInst::ICMP_EQ, Denom, Constant::getNullValue(Denom->getType()));
        Denom = IRB.CreateSelect(IsZero, Constant::getAllOnesValue(Denom->getType()), Denom);
        DenomUse.set(Denom);
      }
    }
  }
  
  void runOnFunction(Function &F) {
    // Ensure that the control-flow graph is a DAG (acyclic).
    removeCyclesInFunction(F);

    // Now, mask accesses to stay in the sandbox region.
    // Pretend the first argument is the sandbox region,
    // and the second is the sandbox mask.
    Value *SandboxBase = F.getArg(0);
    Value *SandboxMask = F.getArg(1);
    IRBuilder<> IRB(&F.getEntryBlock().front());
    SandboxBase = IRB.CreatePtrToInt(SandboxBase, IRB.getInt64Ty());
    SandboxMask = IRB.CreatePtrToInt(SandboxMask, IRB.getInt64Ty());
    maskAccesses(F, SandboxBase, SandboxMask);

    // Now, fix up any division.
    maskDivision(F);

    // Insert MFENCEs.
    auto make_mfence = [&] (Instruction &I) {
      IRBuilder<> IRB(&I);
      return IRB.CreateIntrinsic(IRB.getVoidTy(), Intrinsic::x86_sse2_mfence, {});
    };
    make_mfence(F.getEntryBlock().front());
    for (Instruction &I : instructions(F))
      if (isa<ReturnInst>(&I))
        make_mfence(I);
  }
};

DECLARE_MODULE_PLUGIN(SandboxPass);
