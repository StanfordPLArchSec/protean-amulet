from interfaces import Generator, TestCase
from isa_loader import InstructionSet
from config import CONF
import abc
import subprocess
import re
from generator import X86Generator

class X86LLVMGenerator(Generator):
    def __init__(self, instruction_set: InstructionSet):
        super().__init__(instruction_set)
        if CONF.test_case_generator_seed:
            random.seed(CONF.test_case_generator_seed)

    def create_test_case(self, asm_file: str, i) -> TestCase:
        self.test_case = TestCase()

        stem_file = asm_file.removesuffix(".asm")
        ll_in_file = stem_file + ".in.ll"
        bc_out_file = stem_file + ".out.bc"
        ll_out_file = stem_file + ".out.ll"
        llvm_dir = "../llvm/ptex-17/build/bin"
        llvm_plugin = "../passes/build/libSandboxPass.so"
        subprocess.run([
            f"{llvm_dir}/llvm-stress",
            "-o",
            ll_in_file,
        ], check=True)
        subprocess.run([
            f"{llvm_dir}/opt",
            f"--load-pass-plugin={llvm_plugin}",
            "--passes=SandboxPass",
            ll_in_file,
            "-o", bc_out_file,
        ], check=True)
        subprocess.run([
            f"{llvm_dir}/llvm-dis",
            bc_out_file,
        ], check=True)
        subprocess.run([
            f"{llvm_dir}/llc",
            "--x86-ptex=ct",
            ll_out_file,
            "-o", asm_file,
            "-mattr=-sse,-sse2,-ssse3,-sse4.1,-sse4.2",
        ], check=True)

        # Patch assembly.
        self.patch_asm(asm_file)

        # Assemble into .o
        obj_file = stem_file + ".o"
        bin_file = stem_file + ".bin"
        subprocess.run(f"as {asm_file} -o {obj_file}", shell=True, check=True)

        # objcopy .text .o -> .bin
        subprocess.run(f"objcopy -O binary -j .text {obj_file} {bin_file}", shell=True, check=True)

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
            if line.startswith("autogen_SD0:"):
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

        
