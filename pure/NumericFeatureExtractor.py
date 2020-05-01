#!/home/xianglin/.virtualenvs/angr/bin/ python
# -*- coding: utf-8 -*-
__Auther__ = 'xianglin'

import angr
import capstone
import claripy
from tools.image import Image
from tools.util.asm import is_jump
import redis
import pandas as pd
import csv
import time
import CalIncomingCalls
import os

def cal_arithmetic_insts(block):
    arm64_AI = {'add', 'sub'}
    num = 0
    cs = block.capstone
    insns = cs.insns
    for insn in insns:
        op_type = insn.insn.mnemonic
        if check_type(op_type, arm64_AI):
            num = num + 1
    return num


def get_consts(img, insn, offset):
    string_consts = []
    numeric_consts = []
    insn = insn.insn
    arm64_CI = {'b', 'bl', 'cbz', 'cbnz', 'tbz', 'tbnz'}
    op_imm = {'ARM_OP_IMM', 'ARM64_OP_IMM', 'X86_OP_IMM', 'MIPS_OP_IMM'}
    op_mnemonic = insn.mnemonic
    # if mnemonic is in call functions, return
    if check_type(op_mnemonic, arm64_CI):
        return string_consts, numeric_consts
    base_pointer = {'pc'}
    operand = insn.operands[offset]
    op_type = operand.type
    # if it is an immediate value, output the value
    # contingent across all arch
    if op_type == capstone.arm64.ARM64_OP_IMM:
        # if adr, then string/numeric?, else numeric
        if check_type(op_mnemonic, {'adr'}):
            # turn int to addr hex
            bvv = claripy.BVV(operand.value.imm, 64)
            addr = bvv.args[0]
            string_const = get_string(img, addr)
            if string_const is None:
                numeric_const = get_numeric(img, addr)
                numeric_consts.append(numeric_const)
            else:
                string_consts.append(string_const)
        else:
            numeric_consts.append(operand.value.imm)
    # [mem]
    elif op_type == capstone.arm64.ARM64_OP_MEM:
        if operand.value.mem.base != 0:
            base_reg = insn.reg_name(operand.value.mem.base)
            if base_reg in base_pointer:
                disp = operand.value.mem.disp
                addr = insn.address + disp
                numeric_const = get_numeric(img, addr)
                numeric_consts.append(numeric_const)

    return string_consts, numeric_consts


def get_BB_consts(img, block):
    """
    get string and numeric consts from a block
    Args:
        img(tools.image.Image)
        block: angr.block
    Returns:
        string_consts(list): string consts from a block
        numeric_consts(list): numeric consts from a block
    """
    string_consts = []
    numeric_consts = []
    cs = block.capstone
    insns = cs.insns
    for insn in insns:
        num_operands = len(insn.operands)
        for offset in range(num_operands):
            strings, numerics = get_consts(img, insn, offset)
            string_consts += strings
            numeric_consts += numerics

    return string_consts, numeric_consts


def cal_call_insts(block):
    arm64_CI = {'b', 'bl', 'cbz', 'cbnz', 'tbz', 'tbnz'}
    num = 0
    cs = block.capstone
    insns = cs.insns
    for insn in insns:
        op_type = insn.insn.mnemonic
        if check_type(op_type, arm64_CI):
            num = num + 1
    return num


def cal_logic_insts(block):
    arm64_LI = {'and', 'orr', 'eor', 'xor'}
    num = 0
    cs = block.capstone
    insns = cs.insns
    for insn in insns:
        op_type = insn.insn.mnemonic
        if check_type(op_type, arm64_LI):
            num = num + 1
    return num


def cal_transfer_insts(block):
    arm_TI = {'mvn', "mov"}
    num = 0
    cs = block.capstone
    insns = cs.insns
    for insn in insns:
        op_type = insn.insn.mnemonic
        if check_type(op_type, arm_TI):
            num = num + 1
    return num


def cal_insts(block):
    """calculate the number of instructions in a block"""
    return block.instructions


def cal_lv_size(block):
    """
    calculate the size of local variables
    Args:
        block
    Returns:
        the size of its local variables
    """
    size = 0
    arm64_MI = {'ldr', 'str', 'stp', 'ldp'}   # 'ldrb', 'ldrh', 'strb', 'strh'
    stack_pointer = {'sp'}
    addrs = set()
    cs = block.capstone
    insns = cs.insns
    for insn in insns:
        insn = insn.insn
        op_mnemonic = insn.mnemonic
        if not check_type(op_mnemonic, arm64_MI):
            continue
        # mem load or store
        if op_mnemonic in {'stp', 'ldp'}:
            operand = insn.operands[2]
        else:
            operand = insn.operands[1]
        if operand.type == capstone.arm64.ARM64_OP_MEM:
            if operand.value.mem.base != 0:
                base_reg = insn.reg_name(operand.value.mem.base)
                if base_reg in stack_pointer:
                    disp = operand.value.mem.disp
                    if disp not in addrs:
                        addrs.add(disp)
                        if op_mnemonic == 'ldr' or op_mnemonic == 'str':
                            size = size + 4
                        elif op_mnemonic == 'ldrb' or op_mnemonic == 'strb':
                            size = size + 1
                        elif op_mnemonic == 'ldrh' or op_mnemonic == 'strh':
                            size = size + 2
                        else:
                            addrs.add(disp + 4)
                            size = size + 8
    return size


def cal_incoming_calls(img,func_name, entry):
    """calculate the incoming calls of target function"""
    incoming_calls = 0
    funcs = img.funcs
    funcs.discard(func_name)
    for func in funcs:
        entry_base = img.get_symbol_addr(func)
        if not entry_base:
            return
        cfg = img.get_cfg(func)
        cfg.normalize()
        callgraph = cfg.functions.callgraph
        if entry in list(callgraph):
            incoming_calls = incoming_calls + 1
    return incoming_calls


def feature_extractor(func_cfg, entry_base, incoming_calls):
    func_calls = 0
    logic_instrs = 0
    transfer_instrs = 0
    lv_size = 0
    edges = 0
    instrs = 0


    blocks = len(func_cfg.kb.functions[entry_base].block_addrs_set)
    in_calls = incoming_calls

    for n in func_cfg.nodes():
        if n.function_address == entry_base and n.block is not None:
            func_calls += cal_call_insts(n.block)
            logic_instrs += cal_logic_insts(n.block)
            transfer_instrs += cal_transfer_insts(n.block)
            lv_size += cal_lv_size(n.block)
            instrs += cal_insts(n.block)
            for succ in n.successors:
                if succ.function_address == entry_base and succ.block is not None:
                    edges += 1

    return [func_calls, logic_instrs, transfer_instrs, lv_size, \
           blocks, edges, in_calls, instrs]


def get_bin_features(path, bin_name):
    # TODO when encountering a new binary, we should uncomment this line
    # CalIncomingCalls.cal_incoming_calls(path)
    r = redis.Redis(host='localhost', port=6379, db=1)
    columns = ['bin_name', 'func_name', 'calls', 'logic_instrs', 'transfer_instrs',
               'lv_size', 'blocks', 'edges', 'in_calls', 'instrs']
    img = Image(path)
    funcs = img.funcs

    file_name = "bin_features_" + time.strftime("%Y-%m-%d-%H_%M_%S", time.localtime(time.time())) + '.csv'
    bin_feature_path = './bin_features'
    file_name = os.path.join(bin_feature_path, file_name)
    fileobj = open(file_name, 'w')
    writer = csv.writer(fileobj)
    writer.writerow(columns)

    for func in funcs:
        entry = img.get_symbol_addr(func)
        if not entry:
            continue
        if r.exists(entry) == 0:
            continue
        func_cfg = img.get_cfg(func)
        func_cfg.normalize()
        row = feature_extractor(func_cfg, entry, int(r.get(entry)))
        row.insert(0, func)
        row.insert(0, bin_name)
        writer.writerow(row)

#############################################################
# Auxiliary functions
#############################################################
def check_type(t, t_set):
    """
    Args:
        t(str): operator or register
        t_set(set): check type set
    Returns:
        states(boolean): true if t is in t_set
    """
    for t_type in t_set:
        if t.startswith(t_type):
            return True
    return False


def get_numeric(img, addr):
    b = img.project.loader.memory.load(addr, 4)
    num = int.from_bytes(b, "little")
    return num


def get_string(img, addr):
    string = ""
    for i in range(1000):
        c = img.project.loader.memory.load(addr + i, 1)
        if ord(c) == 0:
            break
        elif 40 <= ord(c) < 128:
            string += chr(ord(c))
        else:
            return None
    return string





if __name__ == "__main__":
    # TODO when encountering a new binary, we should uncomment line 255
    # TODO need to find a way to store all incoming calls of all functions in all binary
    debug_vmlinux = "../testcase/2423496af35d94a87156b063ea5cedffc10a70a1/vmlinux"
    get_bin_features(debug_vmlinux, 'vmlinux')
