'''
配套脚本： toolchain_trace_indirect_jumps.py =》fix_indirect_jump.py 
功能：
根据 frida trace 的日志，解析间接跳转的信息， patch 修复 idb 
'''
import keystone
from capstone import *
import idc
import ida_bytes
import subprocess
import os,datetime
import ida_hexrays
import idautils
import time
import ida_loader
import ida_auto
import ida_pro
import idaapi
from keystone import *
import sys
sys.path.append(sys.path[0]) # 增加当前目录的引用
from ida_helper import *
from collections import *

'''
保存跳转的信息，同一个地址可能跳转到多个目标，并且存在重复，因此用 set 保存. ie: 
{
    0x1234: [0x4567, 0xabcd ]
}
'''
jump_info_map = defaultdict(set)

def apply_patches():
    '''
    根据解析的 jump_info_map 信息 对目标进行 patch.
    根据需要 patch 的指令地址, 做不同处理
    '''
    for insn_addr, jump_targets in jump_info_map.items():
        try:
            jump_targets = list(jump_targets)
            insn = GetDisasm(insn_addr).lower()
            command = "BL "

            if insn.find("blr") > -1:
                pass
            elif insn.find("br") > -1:
                command = "B "
            else:
                continue
            
            if len(jump_targets) > 1:
                print("[!]{} 有多个跳转地址, 可能是虚函数调用".format(hex(insn_addr)))
                # 输出注释
                comm = "{} targets: {}".format(command, " ".join([hex(i) for i in jump_targets]))
                set_cmt(insn_addr, comm, True)

            target_addr = jump_targets[0]
            command += hex(target_addr)
            codes = IDAHelper.asm_factory(KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN, command.encode('utf8'), insn_addr)
            print("patch {} asm {} code: {}".format(hex(insn_addr), command, codes))
            patch_dword(insn_addr, codes)

        except Exception as e:
            print("apply_patches error " + e)

def parse_trace_log2(file_path):
    '''
    解析 日志文件 生成 patch 信息
    '''
    f = open(file_path, encoding='utf8')
    data = f.read()
    f.close()

    # 每一行 message: {'type': 'send', 'payload': '0x1f114c,1f1150'} data: None
    
    for line in data.split("\n"):
        if line:
            parts = line.split("'")[7] # 0xd373c,117d3c
            try:
                insn_addr       = int(parts.split(",")[0], 16)
                jump_target     = int(parts.split(",")[1], 16)
                jump_info_map[insn_addr].add(jump_target)

            except Exception as e:
                print(e)


# 让用户输入 trace 的日志文件路径
trace_log_path = idaapi.ask_file(False, "your log","*")
parse_trace_log2(trace_log_path)
# print(jump_info_map)
apply_patches()
