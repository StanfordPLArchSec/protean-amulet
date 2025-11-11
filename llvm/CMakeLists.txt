cmake_minimum_required(VERSION 3.10)

project(amulet_llvm_pass)

set(CMAKE_CXX_STANDARD 20)

find_package(LLVM REQUIRED CONFIG)

function(add_llvm_library name)
  add_library(${name} ${ARGN})
  target_include_directories(${name} SYSTEM BEFORE PUBLIC ${LLVM_INCLUDE_DIRS})
  target_compile_definitions(${name} PRIVATE ${LLVM_DEFINITIONS})
  target_compile_options(${name} PRIVATE -fno-rtti)
endfunction()

add_llvm_library(Sandbox MODULE Sandbox.cpp)
