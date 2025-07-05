'''
从高到低输出交叉引用最多的函数.
'''
import os,datetime
import ida_hexrays
import idautils
import time
import ida_loader
import ida_auto
import ida_pro
import idaapi
from enum import *
import sys
from collections import *
sys.path.append(sys.path[0]) # 增加当前目录的引用
from ida_helper import *

funs = IDAHelper.get_all_func() # 获取所有函数

n = int(idaapi.ask_str("50", 0, "获取交叉引用排行前N的函数列表"))

print("total {} funs".format(len(funs)))

class sort_by(IntEnum):
    call  = 0
    offset = 1

fun_map = defaultdict(list) # 保存函数对应的交叉引用对象 map

for f in funs:
    fun_map[f] = IDAHelper.get_xrefs_to(f) 

ranks = sorted(fun_map.items(),
                key=lambda x:-len(x[1]))



xrefs_types = set()     # 保存所有交叉引用的数字类型
print("top {} xrefs funs".format(n))
for item in ranks[:n]: 
    print("{} : {}\t{} xrefs".format(IDAHelper.get_ea_name(item[0]),hex(item[0]), len(item[1])))


