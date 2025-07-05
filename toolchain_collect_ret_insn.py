'''
全量遍历模块，查找 ret 指令地址，生成 frida hook 输出返回的 x0 字符串.
'''
import keystone
# from capstone import *
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
from keystone import *
import sys
from bisect import *
import idautils 
script_dir = "\\".join(__file__.split("/")[:-1]) #
sys.path.append(script_dir) # 增加当前目录的引用
sys.path.append("\\".join(script_dir.split(os.sep)[:-1])) # 增加前一个目录的引用
from ida_helper import *
from toolchain_gen_frida_hook import *

def collect_all_ret_addr():
    '''
    收集模块所有的 ret 指令地址
    '''
    ret = [] 
    start, end = IDAHelper.get_exec_seg()

    while start < end:
        cur_insn = GetDisasm(start).lower()
        if cur_insn == "ret":
            ret.append(start)
        start = next_head(start)
    return ret

def collect_export_ret_addr():
    '''
    收集所有导出函数的 ret 指令地址. 注意，有的神奇的函数，在第一个基本块就往上跳转了。。 他的 ret 要向上搜索。。。
    '''
    exports  = list(idautils.Entries())
    ret = []
    for item in exports:
        fun_begin = item[1]
        ret_addr = IDAHelper.find_next_inst_addr(fun_begin, 'ret')
        ret.append(ret_addr)
    return ret


import ida_kernwin

result = ida_kernwin.ask_yn(0, "trace所有函数? No 则仅trace 导出函数.")

rets = []
if result == ida_kernwin.ASKBTN_YES:
    rets = collect_all_ret_addr()
else:
    rets = collect_export_ret_addr()

script = gen_script(rets)
name = os.getcwd()+os.sep+"frida_{}.js".format(time.localtime().tm_sec)
f = open(name, "w")
f.write(script)
f.close()
print("generate to " + name)

