'''
IDA 方法的封装
'''
import os,datetime
import ida_hexrays
import idautils
import time
import ida_loader
import ida_auto
import ida_pro
from keystone import *
from idautils import *
from idaapi import *
from idc import *
import ida_funcs
import sys
import idaapi
from collections import *
import ida_name

fun_set =   set()


class IDAHelper():
    @staticmethod
    def get_seg_begin_end(seg):
        '''
        获取 seg 段起始/结束地址.
        '''
        cur_ea = 0
        while cur_ea != BADADDR:
            name_seg = get_segm_name(cur_ea)
            if name_seg == seg:
                return cur_ea,get_next_seg(cur_ea)
            cur_ea = get_next_seg(cur_ea)
        return 0, 0
    
    @staticmethod
    def get_text_begin():
        '''
        获取 text 段起始地址.
        '''
        cur_ea = 0
        while cur_ea != BADADDR:
            name_seg = get_segm_name(cur_ea)
            if name_seg and name_seg.find("text") != -1:
                return cur_ea
            cur_ea = get_next_seg(cur_ea)
        return 0
    
    @staticmethod
    def find_next_inst_addr(cur_ea, insn):
        '''
        根据当前 ea 找到下一个 insn 指令的地址返回
        :param      cur_ea      起始地址
        :param      insn        搜索的目标指令
        '''
        while cur_ea != idc.BADADDR:
            inst = GetDisasm(cur_ea).lower()
            if inst.find(insn) == -1:
                cur_ea = idc.next_head(cur_ea)
                continue
            return cur_ea

    @staticmethod
    def get_xrefs_to(ea):
        '''
        获取 ea 处的交叉引用信息。 得到可遍历的列表。每个包含字段 'frm', 'iscode', 'to', 'type', 'user'
        注意: 在ARM指令集中，若定义了一个函数指针，那么对于这个函数的引用，其地址需要+1 ！ 否则获取不到 offset 类型的引用！
        XrefTypeName(xref.type) 可以获取引用类型的名字
        Code_Near_Call
        Code_Near_Jump
        Ordinary_Flow
        Data_Offset
        '''
        return list(XrefsTo(ea)) + list(XrefsTo(ea+1))

    @staticmethod
    def get_all_func():
        '''
        获取所有函数的起始地址
        '''
        ea = 0 
        ea =    get_next_func(ea)
        while ea != BADADDR:
            fun_set.add(ea)
            ea =    get_next_func(ea)
        return list(fun_set)


    @staticmethod
    def get_ea_name(ea):
        try:
            return get_name(ea)
        except Exception as e:
            return ''

    @staticmethod
    def get_exec_seg():
        '''
        获取可执行段的起始、结束地址
        '''
        # Traverse all segments
        for seg in idautils.Segments():
            seg_start = idc.get_segm_start(seg)  # Get segment start address
            seg_end = idc.get_segm_end(seg)      # Get segment end address
            seg_name = idc.get_segm_name(seg)    # Get segment name
            seg_perm = idc.get_segm_attr(seg, idc.SEGATTR_PERM)  # Get segment permissions

            # Check for execute permission (bitmask 0x4)
            if seg_perm & 0x1:  # Execute permission bit
                print(f"Executable Segment: {seg_name}")
                print(f"  Start Address: 0x{seg_start:08X}")
                print(f"  End Address: 0x{seg_end:08X}")
                print(f"  Permissions: {seg_perm} (Execute bit set)")
                return seg_start, seg_end
        print("No executable segment found.")
        return 0, 0
    
    
        
    @staticmethod
    def make_comment(addr, comm) :
        '''
        给 addr 添加 注释字符串 comm
        '''
        set_cmt(addr, comm, True)

        