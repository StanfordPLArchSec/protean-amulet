from interfaces import Generator, TestCase
from isa_loader import InstructionSet
from config import CONF
import abc
import subprocess
import re
from generator import X86Generator
import sys
import random
from keystone import Ks, KS_ARCH_X86, KS_MODE_64
import os

max_code_size = 512

class X86LLVMGenerator(Generator):
    def __init__(self, instruction_set: InstructionSet):
        super().__init__(instruction_set)
        if CONF.test_case_generator_seed:
            random.seed(CONF.test_case_generator_seed)

        # assembler stuff
        self.ks = Ks(KS_ARCH_X86, KS_MODE_64)

    def create_test_case(self, asm_file: str, i) -> TestCase:
        while True:
            test_case = self.try_create_test_case(asm_file, i)
            with open(test_case.bin_path, "rb") as f:
                data = f.read()
            if len(data) > max_code_size:
                print(f"[*] test case too long {len(data)}, retrying...")
                continue
            return test_case

    def try_create_test_case(self, asm_file: str, i) -> TestCase:
        self.test_case = TestCase()

        stem_file = asm_file.removesuffix(".asm")
        ll_in_file = stem_file + ".in.ll"
        ll_peel_file = stem_file + ".peel.ll"
        ll_out_file = stem_file + ".out.ll"
        obj_file = stem_file + ".o"
        bin_file = stem_file + ".bin"
        llvm_dir = "../llvm/ptex-17/build/bin"
        llvm_plugin = "../passes/build/libSandboxPass.so"

        # Generate the input.
        subprocess.run([
            f"{llvm_dir}/llvm-stress",
            "-o",
            ll_in_file,
            f"--seed={random.randint(0, 2 ** 32 - 1)}",
        ], check=True)

        # Unpeel/preprocessing.
        # TODO: Can join.
        subprocess.run([
            f"{llvm_dir}/opt",
            "-S",
            "--passes=loop-unroll",
            "--unroll-count=2",
            ll_in_file,
            "-o", ll_peel_file,
        ], check=True)

        # Sandbox the LL.
        subprocess.run([
            f"{llvm_dir}/opt",
            "-S",
            f"--load-pass-plugin={llvm_plugin}",
            "--passes=SandboxPass",
            ll_peel_file,
            "-o", ll_out_file,
        ], check=True)

        # Compile.
        subprocess.run([
            f"{llvm_dir}/llc",
            "--x86-ptex=ct",
            ll_out_file,
            "-o", obj_file,
            "--filetype=obj",
            "-mattr=-sse,-sse2,-ssse3,-sse4.1,-sse4.2",
        ], check=True)

        # objcopy .text .o -> .bin
        subprocess.run(f"objcopy -O binary -j .text {obj_file} {bin_file}", shell=True, check=True)

        # Generate a dummy .asm file from the .bin
        self.make_dummy_asm(bin_file, asm_file)

        # patch binary
        self.patch_bin(bin_file)

        self.test_case.asm_path = asm_file
        self.test_case.bin_path = bin_file

        self.map_addresses(self.test_case, bin_file)

        # Run program just for fun.
        if True:
            subprocess.run(["./harness", bin_file], check=True)

        return self.test_case

    def parse_existing_test_case(self, asm_file: str) -> TestCase:
        raise NotImplementedError("not implemented")

    def map_addresses(self, test_case: TestCase, bin_file: str) -> None:
        X86Generator.map_addresses(self, test_case, bin_file)

    def patch_asm(self, asm_file: str) -> None:
        # Patch the asm file.
        with open(asm_file, "r") as f:
            asm_lines = f.readlines()

        # First, put the right values in rdi, rsi.
        for i, line in enumerate(asm_lines):
            if re.search(r"^autogen_SD\d+:", line):
                break
        assert i + 1 < len(asm_lines)
        print(asm_lines[i + 1])
        ins_idx = i + 2
        assert re.match(r"\s*.cfi_startproc\s*", asm_lines[i + 1])
        asm_lines.insert(ins_idx, "    mov %r14, %rdi\n")
        mask = CONF.input_main_region_size - 1
        asm_lines.insert(ins_idx, f"    mov ${mask}, %rsi\n")

        # Second, add a tail label and replace all RETs with jumps to this label.
        end_label = ".test_end"
        for i, line in enumerate(asm_lines):
            if re.match(r"\s*retq?\s*", line):
                asm_lines[i] = f"jmp {end_label}\n"
        asm_lines.append(f"{end_label}:\n")

        # Write the patched asm to file.
        with open(asm_file, "w") as f:
            f.writelines(asm_lines)


    def patch_bin(self, bin_file: str) -> None:
        # Read the binary.
        with open(bin_file, "rb") as f:
            code = f.read()

        # mov %r14, %rdi
        # mov $mask, %rsi
        mask = CONF.input_main_region_size - 1
        code = bytes(self.ks.asm(f"mov rdi, r14; mov rsi, {mask}")[0]) + code

        # Remove ret at the end.
        assert code[-1] == 0xc3
        code = code[:-1]

        # Write back the binary.
        with open(bin_file, "wb") as f:
            f.write(code)

    def make_dummy_asm(self, bin_file: str, asm_file: str) -> None:
        # Read the binary.
        with open(bin_file, "rb") as f:
            code = f.read()

        # Encode it as a series of .byte directives.
        with open(asm_file, "wt") as f:
            for byte in code:
                print(f"    .byte {byte:#x}", file=f)

