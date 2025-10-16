from interfaces import Generator, TestCase
from generator import X86Generator, ConfigurableGenerator
from config import CONF
import shutil

class X86ConstGenerator(Generator):
    def __init__(self, instruction_set, asm_src):
        super().__init__(instruction_set)
        self.asm_src = asm_src

    def create_test_case(self, asm_file: str, i) -> TestCase:
        self.test_case = TestCase()
        shutil.copyfile(self.asm_src, asm_file)
        stem_file = asm_file.removesuffix(".asm")
        bin_file = stem_file + ".bin"
        self.test_case.asm_path = asm_file
        self.test_case.bin_path = bin_file
        ConfigurableGenerator.assemble(asm_file, bin_file)
        X86Generator.map_addresses(self, self.test_case, bin_file)
        return self.test_case

    def parse_existing_test_case(self, asm_file: str) -> TestCase:
        raise NotImplementedError("not implemented")
