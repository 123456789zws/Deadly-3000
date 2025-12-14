'''
暴力的把 ibr 直接 patch 成 nop。 失去控制流信息，但是可以 F5
流程： 遍历整个函数所有指令， 遇到 BR 则把对应地址 patch_nop.
'''

import idc
import ida_bytes 
import os,datetime
import ida_hexrays
import idautils
import time
import ida_loader
import ida_auto
import ida_pro
import idaapi

import sys
sys.path.append(sys.path[0]) # 增加当前目录的引用
from ida_helper import *
from collections import *



def nop_all_Br(ea):
    '''
    对指定 ea 的函数，把所有 blr 指令 patch 成 nop
    '''
    info  = IDAHelper.get_fun_info(ea)
    cur_ea = info['start']
    fun_end = IDAHelper.search_next_insn(cur_ea, "ret")

    while cur_ea < fun_end:
        cur_insn = GetDisasm(cur_ea).lower()
        cur_insn = cur_insn.replace(" ","")
        if cur_insn.find("brx") > -1:
            IDAHelper.patch_nop(cur_ea)
            print("[+] Patched br at {}".format(hex(cur_ea)))
        cur_ea = next_head(cur_ea)
    
    IDAHelper.merge_fun_range(info['start'], fun_end + 4) # 合并函数
    
    print("[+] Patched all br in function at {} set end to {}".format(hex(ea), hex(fun_end + 4)))

nop_all_Br(here())
