#pragma once

#include <llvm/Pass.h>
#include <llvm/Passes/PassPlugin.h>
#include <llvm/Passes/PassBuilder.h>
#include <llvm/ADT/StringRef.h>

#include <type_traits>

namespace llsct {
  namespace impl {

    template <class Pass>
    void RegisterModulePass(llvm::PassBuilder& PB, llvm::StringRef name) {
      static_assert(std::is_base_of_v<llvm::PassInfoMixin<Pass>, Pass>, "Template type Pass doesn't look like a pass!");
      const auto callback = [&] (llvm::ModulePassManager& MPM, auto) -> bool {
	MPM.addPass(Pass());
	return true;
      };
      const auto parse_callback = [name] (llvm::StringRef pipe_name, llvm::ModulePassManager& MPM, auto) -> bool {
	if (pipe_name == name) {
	  MPM.addPass(Pass());
	  return true;
	} else {
	  return false;
	}
      };
      PB.registerOptimizerLastEPCallback(callback);
      PB.registerFullLinkTimeOptimizationLastEPCallback(callback);
      PB.registerPipelineParsingCallback(parse_callback);
    }

    template <class Pass>
    void RegisterFunctionPass(llvm::PassBuilder& PB, llvm::StringRef name) {
      static_assert(std::is_base_of_v<llvm::PassInfoMixin<Pass>, Pass>, "Template type Pass doesn't look like a pass!");
      const auto callback = [] (llvm::ModulePassManager& MPM, auto) -> bool {
	llvm::FunctionPassManager FPM;
	FPM.addPass(Pass());
	MPM.addPass(createModuleToFunctionPassAdaptor(std::move(FPM)));
	return true;
      };
      const auto parse_callback = [name] (llvm::StringRef pipe_name, llvm::FunctionPassManager& FPM, auto) -> bool {
	if (pipe_name == name) {
	  FPM.addPass(Pass());
	  return true;
	} else {
	  return false;
	}
      };
      PB.registerOptimizerLastEPCallback(callback);
      PB.registerFullLinkTimeOptimizationLastEPCallback(callback);
      PB.registerPipelineParsingCallback(parse_callback);
    }
  }
}

#define DECLARE_MODULE_PLUGIN(Pass)					\
  llvm::PassPluginLibraryInfo llvmGetPassPluginInfo() {			\
    static_assert(llvmGetPassPluginInfo == ::llvmGetPassPluginInfo, "Plugin not declared in top-level namespace!"); \
    const auto cb = [] (llvm::PassBuilder& PB) { ::llsct::impl::RegisterModulePass<Pass>(PB, Pass::name()); }; \
    return {LLVM_PLUGIN_API_VERSION, #Pass, "v0.0", cb};		\
  }

#define DECLARE_FUNCTION_PLUGIN(Pass)					\
  llvm::PassPluginLibraryInfo llvmGetPassPluginInfo() {			\
    static_assert(llvmGetPassPluginInfo == ::llvmGetPassPluginInfo, "Plugin not declared in top-level namespace!"); \
    const auto cb = [] (llvm::PassBuilder& PB) { ::llsct::impl::RegisterFunctionPass<Pass>(PB, Pass::name()); }; \
    return {LLVM_PLUGIN_API_VERSION, #Pass, "v0.0", cb};		\
  }
