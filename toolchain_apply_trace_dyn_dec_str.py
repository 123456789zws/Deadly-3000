'''
把 trace 结果回填到 ida，添加注释及断点，方便搜索字符串。
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
import idaapi
from keystone import *
import sys
sys.path.append(sys.path[0]) # 增加当前目录的引用
from ida_helper import *
from collections import *


trace_log_path = idaapi.ask_file(False, "your log","*")


def parse_line(line:str):
    '''
    解析dump的日志文件中的每一行数据, 是由 dump_bss 函数 生成的：
    输出的日志格式为： offset, comment
    例如：
    1fa030 :  common_key
    '''
    if line.find(":") == -1:
        return 0, ""
    
    parts = line.split(":")
    if len(parts) < 1:
        return 0, ""
    
    try:
        addr = int(parts[0] , 16)
        comment = parts[1]
        return addr, comment
    except Exception as e:
        print("error parse line: " +line + " err: " + str(e))
        return 0, ""



def parse_trace_log(file_path):
    '''
    解析 日志文件 生成 patch 信息
    '''
    f = open(file_path, encoding='utf8')
    data = f.read()
    f.close()
    comments = {}
    patched = 0 
    str_pool  = set()
    line_count = 0

    
    for line in data.split("\n"):
        if line:
            line_count += 1
            # 根据需要，使用不同的行解析函数
            addr, comment = parse_line(line)
            if addr == 0:
                continue
            if len(comment) < 2: ##### 一个字符就不 patch 了
                continue

            if comments.get(addr) == None:
                comments[addr] = set()
            comments[addr].add(comment)
            str_pool.add(comment)



    for addr,v in comments.items():
        # if not get_cmt(addr,True):
        v = list(v)
        comment = " ; ".join(v)
        IDAHelper.make_comment(addr, comment)
        idc.add_bpt(addr)       # 添加断点
        print(f"[{patched}] patch {hex(addr)} \tcomment: {comment}")
        if len(v) > 1:
            print(f"{hex(addr)} has more than one string")
        patched+=1


    print("[+]total {} unique strings found.".format(len(str_pool)))
    print("[+]日志包含 {} 行.".format(line_count))

    print("[+]总共 [{}] 地址解密出字符串, [{}] 备注生效".format(len(comments.keys()), patched))

parse_trace_log(trace_log_path)