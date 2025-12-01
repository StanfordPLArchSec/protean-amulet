"""
File: Model Interface and its implementations

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
from __future__ import annotations
from abc import ABC, abstractmethod

import numpy as np
import unicorn as uni
import copy
import re
import sys
import time
from unicorn import Uc, UcError, UC_MEM_WRITE
import unicorn.x86_const
from unicorn.x86_const import UC_X86_REG_RSP, UC_X86_REG_RBP, \
    UC_X86_REG_RIP, \
    UC_X86_REG_EFLAGS, UC_X86_REG_RAX, UC_X86_REG_RBX, UC_X86_REG_RCX, UC_X86_REG_RDX, \
    UC_X86_REG_RSI, UC_X86_REG_RDI, UC_X86_REG_R8, UC_X86_REG_R9, UC_X86_REG_R10, UC_X86_REG_R11, \
    UC_X86_REG_R12, UC_X86_REG_R13, UC_X86_REG_R14, UC_X86_REG_R15
from typing import List, Tuple, Dict, Optional, Set

from interfaces import CTrace, Input, TestCase, Model, InputTaint, Instruction, RegisterOperand, \
    FlagsOperand, MemoryOperand, ExecutionTrace, TracedInstruction, TracedMemAccess
from generator import X86Registers
from config import CONF, ConfigException
from service import LOGGER
import xxhash
import json
import capstone
import collections
from util import CachingDict

expose_div = False

FLAGS_CF = 0b000000000001
FLAGS_PF = 0b000000000100
FLAGS_AF = 0b000000010000
FLAGS_ZF = 0b000001000000
FLAGS_SF = 0b000010000000
FLAGS_OF = 0b100000000000


# ==================================================================================================
# Abstract Interfaces
# ==================================================================================================
class X86UnicornTracer(ABC):
    trace: List[int]
    execution_trace: ExecutionTrace
    instruction_id: int

    def __init__(self):
        super().__init__()
        self.trace = []

        # Protean extensions.
        self.cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        self.cs.detail = True
        self.regs_access_cache = CachingDict(
            lambda insn: insn.regs_access(),
            key_transform = lambda insn: bytes(insn.bytes),
        )
            
            

    def reset_trace(self, emulator) -> None:
        self.trace = []
        self.execution_trace = []

    def get_contract_trace(self) -> CTrace:
        hasher = xxhash.xxh32()
        for ctrace in self.trace:
            hash_str = hex(ctrace)
            hasher.update(hash_str.encode("utf-8")) # Can only update with bytes
        return hasher.intdigest()
        # return hash(tuple(self.trace))

    def get_contract_trace_array(self):
        return self.trace

    def get_execution_trace(self) -> ExecutionTrace:
        return self.execution_trace

    def add_mem_address_to_trace(self, address: int, model):
        self.trace.append(address)
        model.taint_tracker.taint_memory_access_address()

    def add_pc_to_trace(self, address, model):
        self.trace.append(address)
        model.taint_tracker.taint_pc()

    def observe_mem_access(self, access, address: int, size: int, value: int,
                           model: X86UnicornModel) -> None:
        normalized_address = address - model.sandbox_base
        is_store = (access != uni.UC_MEM_READ)
        val = value if is_store else int.from_bytes(
            model.emulator.mem_read(address, size), byteorder='little')
        LOGGER.dbg_model_mem_access(normalized_address, val, is_store)
        
        if model.in_speculation: # CHECK transient memory access are still real memory accesses?
            return

        if model.execution_tracing_enabled:
            traced_instruction = self.execution_trace[self.instruction_id]
            traced_instruction.accesses.append(TracedMemAccess(normalized_address, val, is_store))

    def observe_instruction(self, address: int, size: int, model) -> None:
        normalized_address = address - model.code_start
        LOGGER.dbg_model_instruction(model.test_case.address_map[normalized_address].name,
                                     normalized_address, model)
        
        if model.in_speculation:
            return

        if model.execution_tracing_enabled:
            self.execution_trace.append(TracedInstruction(normalized_address, []))
            self.instruction_id = len(self.execution_trace) - 1

    def disasm_instruction(self, model):
        address = model.emulator.reg_read(capstone.x86_const.X86_REG_RIP)
        code = model.emulator.mem_read(address, 16)
        return next(iter(self.cs.disasm(code, address)))

    def cs_to_uc_regname(self, cs_reg):
        if cs_reg == "rflags":
            return "eflags"
        # elif cs_reg.startswith("e"):
        #     return "r" + cs_reg.removeprefix("e")
        else:
            return cs_reg
        
    def read_cs_reg(self, cs_reg, model) -> int:
        reg = self.cs.reg_name(cs_reg)
        if reg in ["cs", "ds", "ss", "fs", "gs", "es"]:
            return 0
        uc_regname = self.cs_to_uc_regname(reg)
        uc_reg = eval(f"unicorn.x86_const.UC_X86_REG_{uc_regname.upper()}")
        return model.emulator.reg_read(uc_reg)

    def expose_reg(self, cs_reg, model):
        x = self.read_cs_reg(cs_reg, model)
        self.trace.append(x)
        model.taint_tracker.taint_reg(self.cs.reg_name(cs_reg).upper())

    def expose_mem(self, address, size, model):
        val = int.from_bytes(model.emulator.mem_read(address, size),
                             byteorder="little")
        self.trace.append(val)
        model.taint_tracker.taint_memory_load()

    def regs_access(self, insn):
        return self.regs_access_cache[insn]
        
    def regs_read(self, insn):
        return self.regs_access(insn)[0]

    def regs_write(self, insn):
        return self.regs_access(insn)[1]

        
class X86UnicornModel(Model):
    """
    Base class for all Unicorn-based models.
    Serves as an adapter between Unicorn and our fuzzer.
    """
    # Set in constructor
    CODE_SIZE : int
    WORKING_MEMORY_SIZE : int
    MAIN_REGION_SIZE : int
    ASSIST_REGION_SIZE : int
    OVERFLOW_REGION_SIZE : int

    emulator: Uc
    tracer: X86UnicornTracer
    taint_tracker: TaintTrackerInterface

    test_case: TestCase
    current_instruction: Instruction
    code_start: int
    code_end: int
    sandbox_base: int
    nesting: int = 0
    in_speculation: bool = False
    speculation_window: int = 0
    checkpoints: List
    store_logs: List
    previous_store: Tuple[int, int, int, int]

    # execution modes
    tainting_enabled: bool = False
    execution_tracing_enabled: bool = False

    def __init__(self, sandbox_base, code_start):
        super().__init__(sandbox_base, code_start)
        self.CODE_SIZE = 4 * 1024
        self.MAIN_REGION_SIZE = CONF.input_main_region_size
        self.ASSIST_REGION_SIZE = CONF.input_assist_region_size
        self.OVERFLOW_REGION_SIZE = 4096
        
        # Must be larger than sandbox
        self.WORKING_MEMORY_SIZE = 0x10000000 # 256MB, sync with link1.ld
        
        self.code_start = code_start
        self.sandbox_base = sandbox_base
        print(f"model: {self.sandbox_base=:x}")
        self.lower_overflow_base = self.sandbox_base
        self.main_region = self.lower_overflow_base + self.OVERFLOW_REGION_SIZE
        print(f"model: {self.main_region=:x}")
        self.assist_region_base = self.main_region + self.MAIN_REGION_SIZE
        self.upper_overflow_base = self.assist_region_base + self.ASSIST_REGION_SIZE
        self.stack_base = sandbox_base + self.MAIN_REGION_SIZE - 8
        self.overflow_region_values = bytes(self.OVERFLOW_REGION_SIZE)

        if CONF.contract_observation_clause == 'ctr' or CONF.contract_observation_clause == 'arch':
            self.initial_taints = [
                "A", "B", "C", "D", "SI", "DI", "RSP", "CF", "PF", "AF", "ZF", "SF", "TF", "IF",
                "DF", "OF", "AC"
            ]
        else:
            self.initial_taints = []

    def load_test_case(self, test_case: TestCase) -> None:
        self.test_case = test_case

        # create and read a binary
        with open(test_case.bin_path, 'rb') as f:
            code = f.read()
        self.code_end = self.code_start + len(code)

        # initialize emulator in x86-64 mode
        emulator = Uc(uni.UC_ARCH_X86, uni.UC_MODE_64)

        try:
            # allocate memory
            emulator.mem_map(self.code_start, self.CODE_SIZE)
            # LOGGER.dbg_model("load_test_case", f"Code mapped; self.sandbox_base {self.sandbox_base}, self.WORKING_MEMORY_SIZE: {self.WORKING_MEMORY_SIZE}, self.MAIN_REGION_SIZE: {self.MAIN_REGION_SIZE}")

            # Sandbox address range: 0x502000 - 0x10502000
            # 0x8502000 - (0x10000000 // 2) = 0x502000 (working_region base)
            emulator.mem_map(self.sandbox_base - self.WORKING_MEMORY_SIZE // 2,
                             self.WORKING_MEMORY_SIZE) 

            # write machine code to be emulated to memory
            emulator.mem_write(self.code_start, code)

            # set up callbacks
            emulator.hook_add(uni.UC_HOOK_MEM_READ | uni.UC_HOOK_MEM_WRITE, self.trace_mem_access,
                              self)
            emulator.hook_add(uni.UC_HOOK_CODE, self.instruction_hook, self)

            self.emulator = emulator

        except UcError as e:
            LOGGER.error("[X86UnicornModel:load_test_case] %s" % e)

    def _execute_test_case(self, inputs, nesting, round):
        self.nesting = nesting

        contract_traces: List[CTrace] = []
        execution_traces: List[ExecutionTrace] = []
        taints = []
        for input_ in inputs:
            # self.LOG.dbg_model_header(input_) # Backported; Should be input_id!
            self.reset_model()
            try:
                self._load_input(input_)
                self.reset_model()
                
                if LOGGER.model_debug:
                    # address = 0x1ffc + self.sandbox_base # 0x000 - 0x1000 is first page
                    # val = int.from_bytes(self.emulator.mem_read(address, 4), byteorder='little')
                    # LOGGER.dbg_model("_execute_test_case", f"value of 0x1ffc: {val:#x}")
                    print("DBG: [model]: Initial arch state:", end="")
                    self.print_state()
                    print("")
                
                self.emulator.emu_start(
                    self.code_start, self.code_end, timeout=10 * uni.UC_SECOND_SCALE)
            except UcError as e:
                if not self.in_speculation:
                    self.print_state()
                    LOGGER.waring("model", "[X86UnicornModel:trace_test_case] %s" % e)
                    cs = capstone.Cs(capstone.CS_ARCH_X86,
                                     capstone.CS_MODE_64)
                    pc = self.emulator.reg_read(UC_X86_REG_RIP)
                    code_begin = pc & ~0xFFF
                    code_end = (pc | 0xFFF) + 1
                    code = self.emulator.mem_read(code_begin, code_end - code_begin)
                    for insn in cs.disasm(code, code_begin):
                        marker = "*" if insn.address == pc else " "
                        print(f"{marker} {insn.mnemonic} {insn.op_str}", file=sys.stderr)
                    exit(1)

            # if we use one of the SPEC contracts, we might have some residual simulations
            # that did not reach the spec. window by the end of simulation. Those need
            # to be rolled back
            LOGGER.dbg_model("_execute_test_case", f"Ending speculation state: {self.in_speculation}")
            while self.in_speculation:
                try:
                    self.rollback()
                except uni.UcError:
                    continue
            
            if LOGGER.model_debug:
                print("DBG: [model]: Ending arch state:", end="")
                self.print_state()
                print("")
                
            # store the results
            ctrace = self.tracer.get_contract_trace()
            contract_traces.append(ctrace)
            if CONF.debug:
                ctrace_out_path = "{}/{}/CTrace_{}_{}.out".format(CONF.debug_dir, CONF.test_case, round, input_) # Match to fuzzing round
                # print(f"CTrace out path: {ctrace_out_path}")
                trace_strs = [f"{hex(x)}\n" for x in self.tracer.trace]
                with open(ctrace_out_path, "w") as ctrace_file:
                    ctrace_file.writelines(trace_strs)

            execution_traces.append(self.tracer.get_execution_trace())
            taints.append(self.taint_tracker.get_taint())

        self.coverage.model_hook(execution_traces)

        return contract_traces, taints

    def trace_test_case(self, inputs, nesting, round=0):
        self.execution_tracing_enabled = True
        ctraces, _ = self._execute_test_case(inputs, nesting, round)
        self.execution_tracing_enabled = False
        return ctraces

    def get_taints(self, inputs, nesting):
        self.tainting_enabled = True
        _, taints = self._execute_test_case(inputs, nesting, -1) # -1 since this should not be confused for a result CTrace
        self.tainting_enabled = False
        return taints

    def reset_model(self):
        self.checkpoints = []
        self.in_speculation = False
        self.speculation_window = 0
        self.tracer.reset_trace(self.emulator)
        self.taint_tracker = TaintTracker(self.initial_taints, self.sandbox_base) \
            if self.tainting_enabled else DummyTaintTracker([])

    def _load_input(self, input_: Input):
        LOGGER.dbg_model("_load_input", "Reached entry")
        # Set memory:
        # - initialize overflows with zeroes
        # LOGGER.dbg_model("_load_input", f"self.lower_overflow_base {self.lower_overflow_base}, len(self.overflow_region_values) {len(self.overflow_region_values)}")
        self.emulator.mem_write(self.lower_overflow_base, self.overflow_region_values)
        # LOGGER.dbg_model("_load_input", f"self.upper_overflow_base {self.upper_overflow_base}, len(self.overflow_region_values) {len(self.overflow_region_values)}")
        self.emulator.mem_write(self.upper_overflow_base, self.overflow_region_values)
        # LOGGER.dbg_model("_load_input", "Wrote overflow regions")

        # - sandbox pages
        # LOGGER.dbg_model("_load_input", f"self.sandbox_base: {self.sandbox_base}, len(input_): {len(input_)}")
        self.emulator.mem_write(self.sandbox_base, input_.tobytes())
        # LOGGER.dbg_model("_load_input", "Wrote sandbox")

        # Set values in registers
        registers = [
            UC_X86_REG_RAX, UC_X86_REG_RBX, UC_X86_REG_RCX, UC_X86_REG_RDX, UC_X86_REG_RSI,
            UC_X86_REG_RDI, UC_X86_REG_EFLAGS
        ]
        # print(f"registers for input {input_}: {input_.get_registers()}")
        # print(f"Input data size: {input_.data_size}")
        for i, value in enumerate(input_.get_registers()):
            # print (f"i: {i}, value: {value}")
            if registers[i] == UC_X86_REG_EFLAGS:
                value = (value & np.uint64(2263)) | np.uint64(2)  # type: ignore
            self.emulator.reg_write(registers[i], value)

        self.emulator.reg_write(UC_X86_REG_RSP, self.stack_base)
        self.emulator.reg_write(UC_X86_REG_RBP, self.stack_base)
        self.emulator.reg_write(UC_X86_REG_R14, self.sandbox_base)

    def print_state(self, oneline: bool = False, file = sys.stdout):

        def compressed(val: int):
            if val < self.lower_overflow_base or \
                 val > self.upper_overflow_base + self.OVERFLOW_REGION_SIZE:
                return f"0x{val:<16x}"
            elif val >= self.sandbox_base:
                return f"+0x{val - self.sandbox_base:<15x}"
            else:
                return f"-0x{self.sandbox_base - val:<15x}"

        emulator = self.emulator
        rax = compressed(emulator.reg_read(UC_X86_REG_RAX))
        rbx = compressed(emulator.reg_read(UC_X86_REG_RBX))
        rcx = compressed(emulator.reg_read(UC_X86_REG_RCX))
        rdx = compressed(emulator.reg_read(UC_X86_REG_RDX))
        rsi = compressed(emulator.reg_read(UC_X86_REG_RSI))
        rdi = compressed(emulator.reg_read(UC_X86_REG_RDI))
        rsp = compressed(emulator.reg_read(UC_X86_REG_RSP))

        if not oneline:
            print("\n\nRegisters:",file=file)
            print(f"RAX: {rax}",file=file)
            print(f"RBX: {rbx}",file=file)
            print(f"RCX: {rcx}",file=file)
            print(f"RDX: {rdx}",file=file)
            print(f"RSI: {rsi}",file=file)
            print(f"RDI: {rdi}",file=file)
            print(f"RSP: {rsp}",file=file)
            print(f"EFLAGS={emulator.reg_read(UC_X86_REG_EFLAGS):012b}",file=file)
            
        else:
            print(f"rax={rax} "
                  f"rbx={rbx} "
                  f"rcx={rcx} "
                  f"rdx={rdx} "
                  f"rsi={rsi} "
                  f"rdi={rdi} "
                  f"rsp={rsp} "
                  f"fl={emulator.reg_read(UC_X86_REG_EFLAGS):012b}",file=file)

    @staticmethod
    def instruction_hook(emulator: Uc, address: int, size: int, model: X86UnicornModel) -> None:
        model.current_instruction = model.test_case.address_map[address - model.code_start]
        model.trace_instruction(emulator, address, size, model)

    @staticmethod
    def trace_instruction(emulator: Uc, address: int, size: int, model: X86UnicornModel) -> None:
        pass  # Implemented by subclasses

    @staticmethod
    def trace_mem_access(emulator: Uc, access: int, address: int, size: int, value: int,
                         model: X86UnicornModel) -> None:
        pass  # Implemented by subclasses

    @staticmethod
    def speculate_mem_access(emulator: Uc, access, address, size, value, model):
        pass  # Implemented by subclasses

    @staticmethod
    def speculate_instruction(emulator: Uc, address, size, model) -> None:
        pass  # Implemented by subclasses

    @staticmethod
    def checkpoint(emulator, next_instruction):
        pass  # Implemented by subclasses

    def rollback(self):
        pass  # Implemented by subclasses


# ==================================================================================================
# Tainting
# ==================================================================================================
class TaintTrackerInterface(ABC):

    def __init__(self, initial_observations, sandbox_base=0):
        pass

    def start_instruction(self, instruction: Instruction) -> None:
        pass

    def track_memory_access(self, address: int, size: int, is_write: bool) -> None:
        pass

    def taint_pc(self):
        pass

    def taint_memory_access_address(self):
        pass

    def taint_memory_load(self):
        pass

    def taint_memory_store(self):
        pass

    def taint_reg(self, reg):
        pass

    def checkpoint(self):
        pass

    def rollback(self):
        pass

    @abstractmethod
    def get_taint(self) -> InputTaint:
        pass


class DummyTaintTracker(TaintTrackerInterface):

    def get_taint(self) -> InputTaint:
        return InputTaint()


class TaintTracker(TaintTrackerInterface):
    strict_undefined: bool = True
    _instruction: Optional[Instruction] = None
    sandbox_base: int = 0

    src_regs: List[str]
    dest_regs: List[str]
    reg_dependencies: Dict[str, Set]

    src_flags: List[str]
    dest_flags: List[str]
    flag_dependencies: Dict[str, Set]

    src_mems: List[str]
    dest_mems: List[str]
    mem_dependencies: Dict[str, Set]

    mem_address_regs: List[str]

    tainted_labels: Set[str]
    pending_taint: List[str]

    _reg_decode = {
        "A": UC_X86_REG_RAX,
        "B": UC_X86_REG_RBX,
        "C": UC_X86_REG_RCX,
        "D": UC_X86_REG_RDX,
        "DI": UC_X86_REG_RDI,
        "SI": UC_X86_REG_RSI,
        "SP": UC_X86_REG_RSP,
        "BP": UC_X86_REG_RBP,
        "8": UC_X86_REG_R8,
        "9": UC_X86_REG_R9,
        "10": UC_X86_REG_R10,
        "11": UC_X86_REG_R11,
        "12": UC_X86_REG_R12,
        "13": UC_X86_REG_R13,
        "14": UC_X86_REG_R14,
        "15": UC_X86_REG_R15,
        "FLAGS": UC_X86_REG_EFLAGS,
        "CF": UC_X86_REG_EFLAGS,
        "PF": UC_X86_REG_EFLAGS,
        "AF": UC_X86_REG_EFLAGS,
        "ZF": UC_X86_REG_EFLAGS,
        "SF": UC_X86_REG_EFLAGS,
        "TF": UC_X86_REG_EFLAGS,
        "IF": UC_X86_REG_EFLAGS,
        "DF": UC_X86_REG_EFLAGS,
        "OF": UC_X86_REG_EFLAGS,
        "AC": UC_X86_REG_EFLAGS,
        "RIP": -1,
        "RSP": -1,
    }
    _registers = [
        UC_X86_REG_RAX, UC_X86_REG_RBX, UC_X86_REG_RCX, UC_X86_REG_RDX, UC_X86_REG_RSI,
        UC_X86_REG_RDI, UC_X86_REG_EFLAGS
    ]

    def __init__(self, initial_observations, sandbox_base=0):
        self.initial_observations = initial_observations
        self.sandbox_base = sandbox_base
        self.flag_dependencies = {}
        self.reg_dependencies = {}
        self.mem_dependencies = {}
        self.tainted_labels = set(self.initial_observations)
        self.checkpoints = []

    def start_instruction(self, instruction):
        """ Collect source and target registers/flags """
        if self._instruction:
            self._finalize_instruction()  # finalize the previous instruction

        self._instruction = instruction
        self.src_regs = []
        self.src_flags = []
        self.src_mems = []
        self.dest_regs = []
        self.dest_flags = []
        self.dest_mems = []
        self.pending_taint = []
        self.mem_address_regs = []

        for op in instruction.operands + instruction.implicit_operands:
            if isinstance(op, RegisterOperand):
                value = X86Registers.gpr_normalized[op.value]
                if op.src:
                    self.src_regs.append(value)
                if op.dest:
                    self.dest_regs.append(value)
            elif isinstance(op, FlagsOperand):
                self.src_flags = op.get_read_flags()
                if self.strict_undefined:
                    self.src_flags.extend(op.get_undef_flags())
                self.dest_flags = op.get_write_flags()
            elif isinstance(op, MemoryOperand):
                for sub_op in re.split(r'\+|-|\*| ', op.value):
                    if sub_op and sub_op in X86Registers.gpr_normalized:
                        self.mem_address_regs.append(X86Registers.gpr_normalized[sub_op])

    def _finalize_instruction(self):
        """Propagate dependencies from source operands to destinations """
        # print("-----------------------------------------------")
        # print(self._instruction)
        # print(f"Src:  {self.src_regs}, {self.src_flags}, {self.src_mems}, "
        #   f"Mem regs: {self.mem_address_regs}")
        # print(f"Dest: {self.dest_regs}, {self.dest_flags}, {self.dest_mems}")

        # Compute source label
        src_labels = set()
        for reg in self.src_regs:
            src_labels.update(self.reg_dependencies.get(reg, {reg}))
        for flag in self.src_flags:
            src_labels.update(self.flag_dependencies.get(flag, {flag}))
        for addr in self.src_mems:
            src_labels.update(self.mem_dependencies.get(addr, {addr}))

        # print(src_labels)

        # Propagate label to all targets
        uniq_labels = src_labels
        for reg in self.dest_regs:
            if reg in self.reg_dependencies:
                self.reg_dependencies[reg].update(uniq_labels)
            else:
                self.reg_dependencies[reg] = copy.copy(uniq_labels)
                self.reg_dependencies[reg].add(reg)

        for flg in self.dest_flags:
            if flg in self.flag_dependencies:
                self.flag_dependencies[flg].update(uniq_labels)
            else:
                self.flag_dependencies[flg] = copy.copy(uniq_labels)
                self.flag_dependencies[flg].add(flg)

        for mem in self.dest_mems:
            if mem in self.mem_dependencies:
                self.mem_dependencies[mem].update(uniq_labels)
            else:
                self.mem_dependencies[mem] = copy.copy(uniq_labels)
                self.mem_dependencies[mem].add(mem)

        # Update taints
        for label in self.pending_taint:
            if label.startswith("0x"):
                self.tainted_labels.update(self.mem_dependencies.get(label, {label}))
            else:
                self.tainted_labels.update(self.reg_dependencies.get(label, {label}))

        # print(f"Dep: R{self.reg_dependencies}, F{self.flag_dependencies}, M{self.mem_dependencies}")
        # print(f"Taint: {self.tainted_labels}")

        self._instruction = None

    def track_memory_access(self, address: int, size: int, is_write: bool):
        """ Tracking concrete memory accesses """
        # mask the address - we taint at the granularity of 8 bytes
        address -= self.sandbox_base
        masked_start_addr = address & 0xffff_ffff_ffff_fff8
        end_addr = address + (size - 1)
        masked_end_addr = end_addr & 0xffff_ffff_ffff_fff8

        # add all addresses to tracking
        track_list = self.dest_mems if is_write else self.src_mems
        for i in range(masked_start_addr, masked_end_addr + 1, 8):
            track_list.append(hex(i))

    def taint_pc(self):
        if self._instruction and self._instruction.control_flow:
            self.pending_taint.append("RIP")

    def taint_memory_access_address(self):
        for reg in self.mem_address_regs:
            self.pending_taint.append(reg)

    def taint_memory_load(self):
        for addr in self.src_mems:
            self.pending_taint.append(addr)

    def taint_memory_store(self):
        for addr in self.dest_mems:
            self.pending_taint.append(addr)

    def taint_reg(self, reg):
        if reg in ["SS", "DS", "CS", "FS", "GS"]:
            return
        patterns = [
            r"([ABCD])[XHL]",
            r"R([0-9]+)",
            r"(DI|SI)",
            r"(SP|BP)",
            r"(FLAGS)",
        ]
        for pattern in patterns:
            if m := re.search(pattern, reg):
                self.pending_taint.append(m.group(1))
                return
        raise ValueError(f"unhandled register: {reg}")

    def checkpoint(self):
        if self._instruction:
            self._finalize_instruction()
        self.checkpoints.append(
            (copy.deepcopy(self.flag_dependencies), copy.deepcopy(self.reg_dependencies),
             copy.deepcopy(self.mem_dependencies)))

    def rollback(self):
        assert self.checkpoints, "There are no more checkpoints"
        if self._instruction:
            self._finalize_instruction()
        t = self.checkpoints.pop()
        self.flag_dependencies = copy.deepcopy(t[0])
        self.reg_dependencies = copy.deepcopy(t[1])
        self.mem_dependencies = copy.deepcopy(t[2])

    def get_taint(self) -> InputTaint:
        if self._instruction:
            self._finalize_instruction()

        taint = InputTaint()
        tainted_positions = []
        register_start = taint.register_start

        for label in self.tainted_labels:
            input_offset = -1  # the location of the label within the Input array
            if label.startswith('0x'):
                # memory address
                # we taint the 64-bits block that contains the address
                input_offset = (int(label, 16)) // 8
            else:
                reg = self._reg_decode[label]
                if reg in self._registers:
                    input_offset = register_start + \
                          self._registers.index(self._reg_decode[label])
            if input_offset >= 0:
                tainted_positions.append(input_offset)

        tainted_positions = list(dict.fromkeys(tainted_positions))
        tainted_positions.sort()
        for i in range(taint.size):
            if i in tainted_positions:
                taint[i] = True
            else:
                taint[i] = False

        # print(self.tainted_labels)
        # for i, t in enumerate(taint):
        # if t:
        # print(i)

        return taint


# ==================================================================================================
# Implementation of Observation Clauses
# ==================================================================================================
class L1DTracer(X86UnicornTracer):

    def reset_trace(self, emulator):
        self.trace = [0, 0]
        self.execution_trace = []

    def add_mem_address_to_trace(self, address, model):
        page_offset = (address & 0b111111000000) >> 6
        cache_set_index = 0x8000000000000000 >> page_offset
        # print(f"{cache_set_index:064b}")
        if model.in_speculation:
            self.trace[1] |= cache_set_index
        else:
            self.trace[0] |= cache_set_index
        model.taint_tracker.taint_memory_access_address()

    def observe_mem_access(self, access, address, size, value, model):
        self.add_mem_address_to_trace(address, model)
        super(L1DTracer, self).observe_mem_access(access, address, size, value, model)

    def observe_instruction(self, address: int, size: int, model):
        super(L1DTracer, self).observe_instruction(address, size, model)

    def get_contract_trace(self) -> CTrace: # Actual trace is better than xxhash
        return (self.trace[1] << 64) + self.trace[0]


class PCTracer(X86UnicornTracer):

    def observe_instruction(self, address: int, size: int, model):
        self.add_pc_to_trace(address, model)
        super(PCTracer, self).observe_instruction(address, size, model)


class MemoryTracer(X86UnicornTracer):

    def observe_mem_access(self, access, address, size, value, model):
        self.add_mem_address_to_trace(address, model)
        super(MemoryTracer, self).observe_mem_access(access, address, size, value, model)


class CTTracer(PCTracer):
    def observe_mem_access(self, access, address, size, value, model):
        self.add_mem_address_to_trace(address, model)
        super(CTTracer, self).observe_mem_access(access, address, size, value, model)


class CTNonSpecStoreTracer(PCTracer):
    def observe_mem_access(self, access, address, size, value, model):
        # trace all non-spec mem accesses and speculative loads
        if not model.in_speculation or access == uni.UC_MEM_READ:
            self.add_mem_address_to_trace(address, model)
        super(CTNonSpecStoreTracer, self).observe_mem_access(access, address, size, value, model)


class CTRTracer(CTTracer):
    def reset_trace(self, emulator):
        self.trace = [
            emulator.reg_read(UC_X86_REG_RAX),
            emulator.reg_read(UC_X86_REG_RBX),
            emulator.reg_read(UC_X86_REG_RCX), 
            emulator.reg_read(UC_X86_REG_RDX),
            emulator.reg_read(UC_X86_REG_RSI),
            emulator.reg_read(UC_X86_REG_RDI),
            emulator.reg_read(UC_X86_REG_EFLAGS),
        ]
        self.execution_trace = []

class CTXTracer(CTTracer):
    def reset_trace(self, emulator):
        self.trace = [
            # emulator.reg_read(UC_X86_REG_RBX),
            emulator.reg_read(UC_X86_REG_RBP),
            emulator.reg_read(UC_X86_REG_RSP),
        ]
        self.execution_trace = []

    def observe_instruction(self, address: int, size: int, model):
        super().observe_instruction(address, size, model)
        insn = self.disasm_instruction(model)

        # MEM: Expose base and index address registers.
        for op in insn.operands:
            if op.type == capstone.CS_OP_MEM and \
               op.access & (capstone.CS_AC_READ | capstone.CS_AC_WRITE):
                mem = op.value.mem
                for reg in [mem.base, mem.index]:
                    if reg:
                        self.expose_reg(reg, model)

        # DIV: Expose all register inputs.
        if insn.opcode == capstone.x86_const.X86_INS_DIV and expose_div:
            for reg in self.regs_read(insn):
                self.expose_reg(reg, model)

    def observe_mem_access(self, access, address, size, value, model):
        super().observe_mem_access(access, address, size, value, model)
        insn = self.disasm_instruction(model)

        # DIV: Expose memory inputs.
        if insn.opcode == capstone.x86_const.X86_INS_DIV and expose_div:
            assert access == unicorn.x86_const.UC_MEM_READ
            self.expose_mem(address, size, model)


class ProtTracer(CTRTracer):
    def __init__(self):
        super().__init__()
        self.unprot_regs = []

    def check_protected_pc(self, pc, model) -> bool:
        code = model.emulator.mem_read(pc, 1)
        return code[0] == 0x36

    def cs_to_uc_regname(self, cs_reg):
        if cs_reg == "rflags":
            return "eflags"
        else:
            return cs_reg
        
    def observe_mem_access(self, access, address, size, value, model):
        super().observe_mem_access(access, address, size, value, model)
        if access != uni.UC_MEM_READ:
            return
        pc = model.emulator.reg_read(UC_X86_REG_RIP)
        assert pc == self.last_pc
        if self.check_protected_pc(pc, model):
            return
        # Expose memory.
        self.expose_mem(address, size, model)

    def observe_instruction(self, address: int, size: int, model):
        super().observe_instruction(address, size, model)
        insn = self.disasm_instruction(model)
        self.last_pc = address

        # Expose any outputs from the *last* instruction (HACK!)
        for reg in self.unprot_regs:
            self.expose_reg(reg, model)
        self.unprot_regs = []

        # Expose all address registers.
        for op in insn.operands:
            if op.type == capstone.CS_OP_MEM and \
               op.access & (capstone.CS_AC_READ | capstone.CS_AC_WRITE):
                mem = op.value.mem
                for reg in [mem.base, mem.index]:
                    if reg:
                        self.expose_reg(reg, model)

        # Is the instruction unprotected?
        if not self.check_protected_pc(address, model):
            return

        # Expose ouptut registers, since the instruction is unprotected.
        # But do it before the next instruction executes, since we
        # haven't computed the actual data yet.
        self.unprot_regs = self.regs_write(insn)

class CTSTracer(CTXTracer):
    def __init__(self):
        super().__init__()
        self.clear_analysis()
        self.expand_subregs_cache = CachingDict(self.expand_subregs_impl)
        self.unprot_operands_cache = CachingDict(
            self.get_unprot_operands_impl,
            key_transform=lambda insn: bytes(insn.bytes),
        )

    def clear_analysis(self):
        self.analyzed = False
        self.insns = dict()
        self.succs = collections.defaultdict(set)
        self.unprots_pre = collections.defaultdict(set)
        self.unprots_post = collections.defaultdict(set)

    def reset_trace(self, emulator):
        super().reset_trace(emulator)
        self.clear_analysis()
        
    def get_insns(self, address, model):
        # Get the instructions.
        address_base = address & ~0xFFF
        code_bytes = model.emulator.mem_read(address_base, 0x1000)
        for insn in self.cs.disasm(code_bytes, address_base):
            self.insns[insn.address] = insn

    def lookup_insn(self, address):
        return self.insns.get(address, None)

    def construct_cfg(self):
        for src_insn in self.insns.values():
            if capstone.CS_GRP_JUMP in src_insn.groups:
                assert capstone.CS_GRP_BRANCH_RELATIVE in src_insn.groups
                targets = [src_insn.operands[0].imm]
                if src_insn.opcode != capstone.x86_const.X86_INS_JMP:
                    targets.append(src_insn.address + src_insn.size)
            else:
                targets = [src_insn.address + src_insn.size]

            targets = list(filter(lambda x: x, map(self.lookup_insn, targets)))
            self.succs[src_insn] = targets

    def merge(self, pred):
        for succ in self.succs[pred]:
            self.unprots_post[pred].update(self.unprots_pre[succ])

    def subregs_str(self, reg):
        # subreg maps
        d = [
            # TODO: Add high bytes?
            # r8-r15 subregs
            (r"r(\d+)", ["r{}d"]),
            (r"r(\d+)d", ["r{}w"]),
            (r"r(\d+)w", ["r{}b"]),
            (r"r(\d+)b", []),
            # rax-rdx subregs
            (r"r([abcd])x", ["e{}x"]),
            (r"e([abcd])x", ["{}x"]),
            (r"([abcd])x", ["{}h", "{}l"]),
            (r"[abcd][hl]", []),
            # rdi, rsi subregs
            (r"r([ds])i", ["e{}i"]),
            (r"e([ds])i", ["{}i"]),
            (r"([ds])i", ["{}il"]),
            (r"[ds]il", []),
            # rsp, rbp subregs
            (r"r([sb])p", ["e{}p"]),
            (r"e([sb])p", ["{}p"]),
            (r"([sb])p", ["{}pl"]),
            (r"[sb]pl", []),
            # segment registers
            (r"([cdsefg])s", []),
            # rflags
            (r"rflags", []),
        ]

        l = [reg]
        for pat, subfmts in d:
            if m := re.fullmatch(pat, reg):
                for fmt in subfmts:
                    # print(f"recursing {reg=} {pat=} {fmt=}", file=sys.stderr)
                    subreg = fmt.format(*m.groups())
                    l.extend(self.subregs_str(subreg))
                return l
        raise ValueError(f"failed to match register {reg}")

    def subregs(self, reg):
        subregs_str = self.subregs_str(self.cs.reg_name(reg))
        def f(x):
            if x == "rflags":
                x = "eflags"
            return eval(f"capstone.x86_const.X86_REG_{x.upper()}")
        return list(map(f, subregs_str))

    def get_unprot_operands_impl(self, insn):
        ops = []
        # If it's a branch, then add all inputs.
        if capstone.CS_GRP_JUMP in insn.groups:
            for x in self.regs_read(insn):
                ops.append(x)
        # If it accesses memory, add all memory operands.
        for op in insn.operands:
            if op.access & (capstone.CS_AC_READ | capstone.CS_AC_WRITE):
                if x := op.mem.base:
                    ops.append(x)
                if x := op.mem.index:
                    ops.append(x)
        return ops

    def get_unprot_operands(self, insn):
        return self.unprot_operands_cache[insn]

    def expand_subregs_impl(self, l):
        out = []
        for x in l:
            out.extend(self.subregs(x))
        return out

    # For performance, cache responses from
    # expand_subregs_impl.
    def expand_subregs(self, l):
        return self.expand_subregs_cache[tuple(l)]
            
    def transfer(self, insn):
        v = set(self.unprots_post[insn])

        # Are any defs unprotected?
        unprot_defs = any(map(lambda x: x in v, self.regs_write(insn)))

        # Remove defs.
        for x in self.regs_write(insn):
            v.discard(x)

        # Add in any transmitted operands.
        v.update(self.get_unprot_operands(insn))

        # Add in all uses if a def was unprotected.
        if unprot_defs:
            v.update(self.regs_read(insn))

        if False:
            print(f"DEBUG: {insn.mnemonic} {insn.op_str}: ",
                  *map(self.cs.reg_name, self.regs_write(insn) + self.regs_read(insn)))
            print(f"DEBUG: {unprot_defs=}")
            print(f"DEBUG: unprot_pre:", *map(self.cs.reg_name, self.unprots_pre[insn]))
            print(f"DEBUG: unprot_post:", *map(self.cs.reg_name, self.unprots_post[insn]))

        self.unprots_pre[insn] = set(self.expand_subregs(v))

    def dataflow_snapshot(self):
        return (dict(self.unprots_pre.items()),
                dict(self.unprots_post.items()))
                    
    def dataflow_analysis_one(self):
        old = self.dataflow_snapshot()
        for _, insn in sorted(self.insns.items(), reverse=True):
            self.merge(insn)
            self.transfer(insn)
        new = self.dataflow_snapshot()
        return old != new

    def dataflow_analysis(self):
        t0 = time.process_time()
        num_iters = 0
        while changed := self.dataflow_analysis_one():
            num_iters += 1
            if num_iters > 1000:
                raise RuntimeError("dataflow analysis braindead")
            pass
        t1 = time.process_time()
        print(f"\ndataflow analysis time: {t1-t0}s", file=sys.stderr)

    def print_analysis(self):
        addrs = sorted(list(self.insns.keys()))
        
        # Print the successor map.
        for addr in addrs:
            insn = self.insns[addr]
            succs = map(lambda x: f"{x.address:#x}", self.succs[insn])
            print(f"CFG: {addr:#x} ->", *succs)
        print("-----")
        
        # Print the data-flow. 
        for addr in sorted(list(self.insns.keys())):
            insn = self.insns[addr]
            unprot_regs = map(self.cs.reg_name,
                              self.unprots_pre[insn])
            print("#", *unprot_regs)
            print(f"{insn.address:#x} {insn.mnemonic} {insn.op_str}")

    def analyze_binary(self, address: int, model):
        self.get_insns(address, model)
        self.construct_cfg()
        self.dataflow_analysis()
        if CONF.verbose:
            self.print_analysis()
        
    def observe_instruction(self, address: int, size: int, model):
        if not self.analyzed:
            self.analyze_binary(address, model)
            self.analyzed = True

        super().observe_instruction(address, size, model)

        # Expose all unprotected registers.
        if insn := self.lookup_insn(address):
            for reg in self.unprots_pre[insn]:
                self.expose_reg(reg, model)

                        
class ArchTracer(CTRTracer):
    def observe_mem_access(self, access, address, size, value, model: X86UnicornModel):
        if access == uni.UC_MEM_READ:
            self.expose_mem(address, size, model)
        self.add_mem_address_to_trace(address, model)
        super(ArchTracer, self).observe_mem_access(access, address, size, value, model)


# ==================================================================================================
# Implementation of Execution Clauses
# ==================================================================================================
class X86UnicornSeq(X86UnicornModel):
    """
    A simple, in-order contract.
    The only thing it does is tracing.
    No manipulation of the control or data flow.
    """

    @staticmethod
    def trace_instruction(emulator, address, size, model) -> None:
        model.taint_tracker.start_instruction(model.current_instruction)
        model.tracer.observe_instruction(address, size, model)

    @staticmethod
    def trace_mem_access(emulator, access, address: int, size, value, model):
        model.taint_tracker.track_memory_access(address, size, access == UC_MEM_WRITE)
        model.tracer.observe_mem_access(access, address, size, value, model)


class X86UnicornSpec(X86UnicornModel):
    """
    Intermediary class for all speculative contracts.
    Tracks speculative stores
    """

    def __init__(self, *args):
        self.checkpoints = []
        self.store_logs = []
        self.previous_store = (0, 0, 0, 0)
        self.latest_rollback_address = 0
        super(X86UnicornSpec, self).__init__(*args)

    @staticmethod
    def trace_mem_access(emulator, access, address, size, value, model):
        # when in speculation, log all changes to memory
        if access == UC_MEM_WRITE and model.store_logs:
            model.store_logs[-1].append((address, emulator.mem_read(address, 8)))

        X86UnicornSeq.trace_mem_access(emulator, access, address, size, value, model)
        model.speculate_mem_access(emulator, access, address, size, value, model)

    @staticmethod
    def trace_instruction(emulator, address, size, model) -> None:
        if model.in_speculation:
            model.speculation_window += 1
            # rollback on a serializing instruction
            if model.current_instruction.name in ["LFENCE", "MFENCE"]:
                emulator.emu_stop()

            # and on expired speculation window
            if model.speculation_window > CONF.model_max_spec_window:
                emulator.emu_stop()

        X86UnicornSeq.trace_instruction(emulator, address, size, model)
        model.speculate_instruction(emulator, address, size, model)

    def checkpoint(self, emulator, next_instruction):
        flags = emulator.reg_read(UC_X86_REG_EFLAGS)
        context = emulator.context_save()
        spec_window = self.speculation_window
        self.checkpoints.append((context, next_instruction, flags, spec_window))
        self.store_logs.append([])
        self.in_speculation = True
        self.taint_tracker.checkpoint()

    def rollback(self):
        # restore register values
        state, next_instr, flags, spec_window = self.checkpoints.pop()
        if not self.checkpoints:
            self.in_speculation = False

        # self.LOG.dbg_model_rollback(next_instr, self.code_start)
        self.latest_rollback_address = next_instr

        # restore the speculation state
        self.emulator.context_restore(state)
        self.speculation_window = spec_window

        # rollback memory changes
        mem_changes = self.store_logs.pop()
        while mem_changes:
            addr, val = mem_changes.pop()
            self.emulator.mem_write(addr, bytes(val))

        # if there are any pending speculative store bypasses, cancel them
        self.previous_store = (0, 0, 0, 0)

        # restore the flags last, to avoid corruption by other operations
        self.emulator.reg_write(UC_X86_REG_EFLAGS, flags)

        # restore the taint tracking
        self.taint_tracker.rollback()

        # restart without misprediction
        self.emulator.emu_start(next_instr, self.code_end, timeout=10 * uni.UC_SECOND_SCALE)

    def reset_model(self):
        super().reset_model()
        self.latest_rollback_address = 0


class X86UnicornCond(X86UnicornSpec):
    """
    Contract for conditional branch mispredicitons.
    Forces all cond. branches to speculatively go into a wrong target
    """

    jumps = {
        # c - the byte code of the instruction
        # f - the value of EFLAGS
        0x70: lambda c, f, r: (c[1:], f & FLAGS_OF != 0, False),  # JO
        0x71: lambda c, f, r: (c[1:], f & FLAGS_OF == 0, False),  # JNO
        0x72: lambda c, f, r: (c[1:], f & FLAGS_CF != 0, False),  # JB
        0x73: lambda c, f, r: (c[1:], f & FLAGS_CF == 0, False),  # JAE
        0x74: lambda c, f, r: (c[1:], f & FLAGS_ZF != 0, False),  # JZ
        0x75: lambda c, f, r: (c[1:], f & FLAGS_ZF == 0, False),  # JNZ
        0x76: lambda c, f, r: (c[1:], f & FLAGS_CF != 0 or f & FLAGS_ZF != 0, False),  # JNA
        0x77: lambda c, f, r: (c[1:], f & FLAGS_CF == 0 and f & FLAGS_ZF == 0, False),  # JNBE
        0x78: lambda c, f, r: (c[1:], f & FLAGS_SF != 0, False),  # JS
        0x79: lambda c, f, r: (c[1:], f & FLAGS_SF == 0, False),  # JNS
        0x7A: lambda c, f, r: (c[1:], f & FLAGS_PF != 0, False),  # JP
        0x7B: lambda c, f, r: (c[1:], f & FLAGS_PF == 0, False),  # JPO
        0x7C: lambda c, f, r: (c[1:], (f & FLAGS_SF == 0) != (f & FLAGS_OF == 0), False),  # JNGE
        0x7D: lambda c, f, r: (c[1:], (f & FLAGS_SF == 0) == (f & FLAGS_OF == 0), False),  # JNL
        0x7E: lambda c, f, r:
        (c[1:], f & FLAGS_ZF != 0 or (f & FLAGS_SF == 0) != (f & FLAGS_OF == 0), False),
        0x7F: lambda c, f, r:
        (c[1:], f & FLAGS_ZF == 0 and (f & FLAGS_SF == 0) == (f & FLAGS_OF == 0), False),
        0xE0: lambda c, f, r: (c[1:], r != 1 and (f & FLAGS_ZF == 0), True),  # LOOPNE
        0xE1: lambda c, f, r: (c[1:], r != 1 and (f & FLAGS_ZF != 0), True),  # LOOPE
        0xE2: lambda c, f, r: (c[1:], r != 1, True),  # LOOP
        0xE3: lambda c, f, r: (c[1:], r == 0, False),  # J*CXZ
        0x0F: lambda c, f, r:
        X86UnicornCond.multibyte_jmp.get(c[1], (lambda _, __, ___: ([0], False, False)))(c, f, r)
    }  # yapf: disable

    multibyte_jmp: Dict = {
        0x80: lambda c, f, r: (c[2:], f & FLAGS_OF != 0, False),  # JO
        0x81: lambda c, f, r: (c[2:], f & FLAGS_OF == 0, False),  # JNO
        0x82: lambda c, f, r: (c[2:], f & FLAGS_CF != 0, False),  # JB
        0x83: lambda c, f, r: (c[2:], f & FLAGS_CF == 0, False),  # JAE
        0x84: lambda c, f, r: (c[2:], f & FLAGS_ZF != 0, False),  # JE
        0x85: lambda c, f, r: (c[2:], f & FLAGS_ZF == 0, False),  # JNE
        0x86: lambda c, f, r: (c[2:], f & FLAGS_CF != 0 or f & FLAGS_ZF != 0, False),  # JBE
        0x87: lambda c, f, r: (c[2:], f & FLAGS_CF == 0 and f & FLAGS_ZF == 0, False),  # JA
        0x88: lambda c, f, r: (c[2:], f & FLAGS_SF != 0, False),  # JS
        0x89: lambda c, f, r: (c[2:], f & FLAGS_SF == 0, False),  # JNS
        0x8A: lambda c, f, r: (c[2:], f & FLAGS_PF != 0, False),  # JP
        0x8B: lambda c, f, r: (c[2:], f & FLAGS_PF == 0, False),  # JPO
        0x8C: lambda c, f, r: (c[2:], (f & FLAGS_SF == 0) != (f & FLAGS_OF == 0), False),  # JNGE
        0x8D: lambda c, f, r: (c[2:], (f & FLAGS_SF == 0) == (f & FLAGS_OF == 0), False),  # JNL
        0x8E: lambda c, f, r:
        (c[2:], f & FLAGS_ZF != 0 or (f & FLAGS_SF == 0) != (f & FLAGS_OF == 0), False),
        0x8F: lambda c, f, r:
        (c[2:], f & FLAGS_ZF == 0 and (f & FLAGS_SF == 0) == (f & FLAGS_OF == 0), False),
    }  # yapf: disable

    @staticmethod
    def speculate_instruction(emulator: Uc, address, size, model) -> None:
        # reached max spec. window? skip
        if len(model.checkpoints) >= model.nesting:
            return

        # decode the instruction
        code = emulator.mem_read(address, size)
        flags = emulator.reg_read(UC_X86_REG_EFLAGS)
        rcx = emulator.reg_read(UC_X86_REG_RCX)
        target, will_jump, is_loop = X86UnicornCond.decode(code, flags, rcx)

        # not a a cond. jump? ignore
        if not target:
            return

        # LOOP instructions must also decrement RCX
        if is_loop:
            emulator.reg_write(UC_X86_REG_RCX, rcx - 1)

        # Take a checkpoint
        next_instr = address + size + target if will_jump else address + size
        model.checkpoint(emulator, next_instr)

        # Simulate misprediction
        if will_jump:
            emulator.reg_write(UC_X86_REG_RIP, address + size)
        else:
            emulator.reg_write(UC_X86_REG_RIP, address + size + target)

    @staticmethod
    def decode(code: bytearray, flags: int, rcx: int) -> Tuple[int, bool, bool]:
        """
        Decodes the instruction encoded in `code` and, if it's a conditional jump,
        returns its expected target, whether it will jump to the target (based
        on the `flags` value), and whether it is a LOOP instruction
        """
        calculate_target = X86UnicornCond.jumps.get(code[0], (lambda _, __, ___:
                                                              ([0], False, False)))
        target, will_jump, is_loop = calculate_target(code, flags, rcx)
        if len(target) == 1:
            return target[0], will_jump, is_loop
        return int.from_bytes(target, byteorder='little'), will_jump, is_loop


class X86UnicornBpas(X86UnicornSpec):

    @staticmethod
    def speculate_mem_access(emulator, access, address, size, value, model):
        """
        Since Unicorn does not have post-instruction hooks,
        I have to implement it in a dirty way:
        Save the information about the store here, but execute all the
        contract logic in a hook before the next instruction (see trace_instruction)
        """
        if access == UC_MEM_WRITE:
            rip = emulator.reg_read(UC_X86_REG_RIP)
            opcode = emulator.mem_read(rip, 1)[0]
            if opcode not in [0xE8, 0xFF, 0x9A]:  # ignore CALL instructions
                model.previous_store = (address, size, emulator.mem_read(address, size), value)

    @staticmethod
    def speculate_instruction(emulator: Uc, address, size, model) -> None:
        # reached max spec. window? skip
        if len(model.checkpoints) >= model.nesting:
            return

        if model.previous_store[0]:
            store_addr = model.previous_store[0]
            old_value = bytes(model.previous_store[2])
            new_is_signed = model.previous_store[3] < 0
            new_value = (model.previous_store[3]). \
                to_bytes(model.previous_store[1], byteorder='little', signed=new_is_signed)

            # store a checkpoint
            model.checkpoint(emulator, address)

            # cancel the previous store but preserve its value
            emulator.mem_write(store_addr, old_value)
            model.store_logs[-1].append((store_addr, new_value))
        model.previous_store = (0, 0, 0, 0)


class X86UnicornNull(X86UnicornSpec):
    instruction_address: int

    @staticmethod
    def speculate_mem_access(emulator, access, address, size, value, model):
        # reached max spec. window? skip
        if len(model.checkpoints) >= model.nesting:
            return

        # applicable only to loads
        if access == UC_MEM_WRITE:
            return

        # make sure we do not repeat the same injection all over again
        if model.instruction_address == model.latest_rollback_address:
            return

        # store a checkpoint
        model.checkpoint(emulator, model.instruction_address)
        model.store_logs[-1].append((address, emulator.mem_read(address, 8)))

        # emulate zero-injection by writing zero to the target address of the load
        zero_value = bytes([0 for _ in range(size)])
        emulator.mem_write(address, zero_value)

    @staticmethod
    def speculate_instruction(emulator: Uc, address, size, model) -> None:
        model.instruction_address = address


class X86UnicornCondBpas(X86UnicornSpec):

    @staticmethod
    def speculate_mem_access(emulator, access, address, size, value, model):
        X86UnicornBpas.speculate_mem_access(emulator, access, address, size, value, model)

    @staticmethod
    def speculate_instruction(emulator: Uc, address, size, model) -> None:
        X86UnicornCond.speculate_instruction(emulator, address, size, model)
        X86UnicornBpas.speculate_instruction(emulator, address, size, model)


def get_model(bases: Tuple[int, int]) -> Model:
    if CONF.model == 'x86-unicorn':
        model: Model

        # functional part of the contract
        if "cond" in CONF.contract_execution_clause and "bpas" in CONF.contract_execution_clause:
            model = X86UnicornCondBpas(bases[0], bases[1])
        elif "cond" in CONF.contract_execution_clause:
            model = X86UnicornCond(bases[0], bases[1])
        elif "bpas" in CONF.contract_execution_clause:
            model = X86UnicornBpas(bases[0], bases[1])
        elif "cond-bpas" in CONF.contract_execution_clause:
            model = X86UnicornCondBpas(bases[0], bases[1])
        elif "null-injection" in CONF.contract_execution_clause:
            model = X86UnicornNull(bases[0], bases[1])
        elif "seq" in CONF.contract_execution_clause:
            model = X86UnicornSeq(bases[0], bases[1])
        else:
            ConfigException("unknown value of `contract_execution_clause` configuration option")
            exit(1)

        # observational part of the contract
        if CONF.contract_observation_clause == "l1d":
            model.tracer = L1DTracer()
        elif CONF.contract_observation_clause == 'pc':
            model.tracer = PCTracer()
        elif CONF.contract_observation_clause == 'memory':
            model.tracer = MemoryTracer()
        elif CONF.contract_observation_clause == 'ct':
            model.tracer = CTTracer()
        elif CONF.contract_observation_clause == 'ctx':
            model.tracer = CTXTracer()
        elif CONF.contract_observation_clause == 'ct-nonspecstore':
            model.tracer = CTNonSpecStoreTracer()
        elif CONF.contract_observation_clause == 'ctr':
            model.tracer = CTRTracer()
        elif CONF.contract_observation_clause == 'arch':
            model.tracer = ArchTracer()
        elif CONF.contract_observation_clause == 'prot':
            model.tracer = ProtTracer()
        elif CONF.contract_observation_clause == 'cts':
            model.tracer = CTSTracer()
        else:
            ConfigException("unknown value of `contract_observation_clause` configuration option")
            exit(1)

        return model
    else:
        ConfigException("unknown value of `model` configuration option")
        exit(1)
