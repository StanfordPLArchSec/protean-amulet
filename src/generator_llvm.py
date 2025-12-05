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
from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_GRP_JUMP
from capstone.x86_const import X86_INS_RET, X86_INS_JMP
import os
import shutil

max_code_size = 512
llvm_dir = "../llvm/ptex-17/build/bin"
optimize = True

class X86LLVMGenerator(Generator):
    def __init__(self, instruction_set: InstructionSet, protcc: str):
        super().__init__(instruction_set)
        if CONF.test_case_generator_seed:
            random.seed(CONF.test_case_generator_seed)

        self.ptex_mode = protcc

        # assembler stuff
        self.ks = Ks(KS_ARCH_X86, KS_MODE_64)
        self.cs = Cs(CS_ARCH_X86, CS_MODE_64)
        self.cs.detail = True

    def create_test_case(self, asm_file: str, i) -> TestCase:
        while True:
            if test_case := self.try_create_test_case(asm_file, i):
                return test_case
                # print("success")

    def try_create_test_case(self, asm_file: str, i) -> TestCase:
        self.test_case = TestCase()

        stem_file = asm_file.removesuffix(".asm")
        ll_in_file = stem_file + ".in.ll"
        ll_peel_file = stem_file + ".peel.ll"
        ll_out_file = stem_file + ".out.ll"
        obj_file = stem_file + ".o"
        bin_file = stem_file + ".bin"
        llvm_plugin = "build/libSandboxPass.so"

        # Generate the input.
        subprocess.run([
            f"{llvm_dir}/llvm-stress",
            "-o",
            ll_in_file,
            f"--seed={random.randint(0, 2 ** 32 - 1)}",
            # f"--size={50}",
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

        # Optimize.
        if optimize:
            ll_unopt_file = stem_file + ".unopt.ll"
            shutil.move(ll_out_file, ll_unopt_file)
            subprocess.run([
                f"{llvm_dir}/opt",
                "-S",
                f"--O1",
                ll_unopt_file,
                "-o", ll_out_file,
            ], check=True)

        # Compile.
        if not self.compile_llc(ll_out_file, obj_file):
            print("[*] failed to compile binary")
            return None

        # objcopy .text .o -> .bin
        subprocess.run(f"objcopy -O binary -j .text {obj_file} {bin_file}", shell=True, check=True)

        # patch binary
        if not self.patch_bin(bin_file):
            print("[*] failed to patch binary")
            return None

        self.test_case.asm_path = asm_file
        self.test_case.bin_path = bin_file

        # Check binary length.
        with open(bin_file, "rb") as f:
            data = f.read()
            if len(data) > max_code_size:
                print(f"[*] test case too long ({len(data)} bytes)")
                return None

        self.map_addresses(self.test_case, bin_file)

        # Generate a dummy .asm file from the .bin
        self.make_dummy_asm(bin_file, asm_file)

        # Run program just for fun.
        if not self.check_harness(bin_file):
            print(f"[*] test harness failed")
            return None

        return self.test_case

    def parse_existing_test_case(self, asm_file: str) -> TestCase:
        self.reset_generator()
        test_case = TestCase()
        test_case.asm_path = asm_file
        test_case.bin_path = bin_file = asm_file.removesuffix(".asm") + ".bin"
        X86Generator.assemble(asm_file, bin_file)
        self.map_addresses(test_case, bin_file)
        return test_case

    def map_addresses(self, test_case: TestCase, bin_file: str) -> None:
        X86Generator.map_addresses(self, test_case, bin_file)

    def reset_generator(self):
        pass

    def patch_bin(self, bin_file: str) -> bool:
        # Read the binary.
        with open(bin_file, "rb") as f:
            code = f.read()

        # mov %r14, %rdi
        # mov $mask, %rsi
        mask = (CONF.input_main_region_size - 1) & ~0b111
        # mov [rdi + 0x1000], rsp
        # mov [rdi
        prologue = [
            "mov rdi, r14",
            f"mov rsi, {mask}",
            "mov rbx, 0",
            "lea rsp, [rdi+rsi]",
            ".byte 0x36; mov rdx, rdx",
            ".byte 0x36; mov rcx, rcx",
            # "mov r8, 0",
            # "mov r9, 0",
        ]
        for reg in ['r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15', 'rbp']:
            prologue.append(f'mov {reg}, 0')
        code = bytes(self.ks.asm("; ".join(prologue))[0]) + code
        # code = bytes(self.ks.asm(f"mov rdi, r14; mov rsi, {mask}; mov rbx, 0")[0]) + code

        # Remove ret at the end.
        insns = list(self.cs.disasm(code, 0))
        if insns[-1].id != X86_INS_RET:
            # Regenerate if we don't end in a RET.
            print("[*] didn't end in ret")
            return False
        for insn in insns[:-1]:
            if insn.id == X86_INS_RET:
                # Internal ret! Regenerate!
                print("[*] internal ret")
                return False
        assert code[-1] == 0xc3
        code = code[:-1]

        # Was there a conditional jump? If not, fail.
        jccs = 0
        for insn in insns:
            if insn.group(CS_GRP_JUMP) and \
               insn.id != X86_INS_JMP:
                jccs += 1
        if jccs == 0:
            print("[*] no jump")
            return False
                

        # Write back the binary.
        with open(bin_file, "wb") as f:
            f.write(code)

        return True

    def make_dummy_asm(self, bin_file: str, asm_file: str) -> None:
        # Read the binary.
        with open(bin_file, "rb") as f:
            code = f.read()

        # Encode it as a series of .byte directives.
        with open(asm_file, "wt") as f:
            for byte in code:
                print(f"    .byte {byte:#x}", file=f)


    def compile_llc(self, ll_file, obj_file) -> bool:
        llc_result = subprocess.run([
            f"{llvm_dir}/llc",
            f"--x86-ptex={self.ptex_mode}",
            ll_file,
            "-o", obj_file,
            "--filetype=obj",
            "-mattr=-sse,-sse2,-ssse3,-sse4.1,-sse4.2",
        ], text=True, stderr=subprocess.PIPE)
        if llc_result.returncode == 0:
            return True

        # Why did it fail?
        def check_line(line):
            # Empty line?
            if re.match(r"\s*", line):
                return True
            # Clang SSE bug?
            if re.match(r"error: <unknown>:0:0: in function autogen_SD\d+ void (ptr, ptr, ptr, i32, i64, i8): SSE register return with SSE disabled", line):
                return True
            return False

        if all(map(check_line, llc_result.stderr.split("\n"))):
            # It failed because of the SSE error.
            return False

        # Otherwise, we encountered an unknown error.
        print(llc_result.stderr, file=sys.stderr)
        llc_result.check()
        assert False # unreachable

    def check_harness(self, bin_file) -> bool:
        # TODO: This sometimes fails due to LLVM putting constants
        # in a separate text section.
        result = subprocess.run(["./harness", bin_file])
        return result.returncode == 0
        
