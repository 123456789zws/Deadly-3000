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

    
    @staticmethod
    def patch_nop(ea, count=1):
        '''
        arm64下， 在 ea 处 patch count条指令为 nop 指令，默认1条
        '''
        code = IDAHelper.asm_factory(KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN, "nop".encode('utf8'))
        for t in range(count):
            patch_dword(ea + 4*t, code)
            IDAHelper.make_code(ea + 4*t)

    
    @staticmethod
    def asm_factory(arch, mode, code, addr=0, syntax = 0):
        '''
        各平台架构的汇编器工厂. 返回 int 数字表示指令
        @param  code    汇编代码
        @param  addr    指令所在地址，会影响 adr 等 pc 相关指令的生成
        '''
        ks = Ks(arch, mode)
        if syntax != 0:
            ks.syntax = syntax
        
        encoding, count = ks.asm(code, addr)
        print("%s = [ " % code, end='')
        for i in encoding:
            print("%02x " % i, end='')
        print("]")
        return int.from_bytes(bytes(encoding), 'little')


    @staticmethod
    def make_code(ea):
        '''
        设置 ea 处为指令
        '''
        try:
            create_insn(ea)
        except Exception as e:
            print("make_code error " + e)

    @staticmethod
    def search_next_insn(start_ea, insn:str):
        '''
        从 start_ea 搜索 吓一跳 insn 出现的地址
        '''
        end_ea = BADADDR
        insn = insn.lower()
        cur_ea = start_ea
        while cur_ea != end_ea:
            cur_insn = GetDisasm(cur_ea).lower()
            if cur_insn.find(insn) > -1:
                print("{} {}".format(hex(cur_ea), cur_insn))
                return cur_ea
            cur_ea = next_head(cur_ea)
        
        return BADADDR

    
    @staticmethod
    def get_fun_info(ea):
        '''
        获取函数的信息
        '''
        r = {'start':0, 'end':0, 'flags':0,'frame':0,  # frame id
        'frsize':0, # 局部变量大小
        'argsize': 0, # 参数大小
        'fpd' : 0,# frame pointer delta
        'frregs': 0, # 保存的寄存器空间大小
        }
        try:
            r['start'] = get_func_attr(ea, FUNCATTR_START)
            r['end'] = get_func_attr(ea, FUNCATTR_END      )
            r['flags'] = get_func_attr(ea,  FUNCATTR_FLAGS   )
            r['frame'] = get_func_attr(ea, FUNCATTR_FRAME   )
            r['frsize'] = get_func_attr(ea, FUNCATTR_FRSIZE  )
            r['argsize'] = get_func_attr(ea, FUNCATTR_ARGSIZE )
            r['fpd'] = get_func_attr(ea, FUNCATTR_FPD     )
            r['frregs'] = get_func_attr(ea, FUNCATTR_FRREGS  )
            r['name']   =   IDAHelper.get_ea_name(r['start'])
        except Exception as e:
            pass
        return r

    @staticmethod
    def merge_fun_range(start_ea, end_ea):
        '''
        根据当前函数开始地址，搜索下一个函数NF，若NF结束地址小于等于 end_ea ， 则添加到当前函数的 children 列表中。
        搜索结束后，合并所有函数。
        '''
        cur_fun = IDAHelper.get_fun_info(start_ea)
        cur_ea = cur_fun['start']
        next_ea = get_next_func(cur_ea)
        children  = set()
        
        while True:
            info = IDAHelper.get_fun_info(next_ea)
            if info and info['start'] <= end_ea:
                children.add(info['start'])
                next_ea = get_next_func(next_ea)
            else:
                break
        
        print("[+]total {} functions to merge".format(len(children)))
        IDAHelper.merge_funcs(cur_ea, list(children))

    @staticmethod
    def merge_funcs(parent, children):
        '''
        把 children 函数列表, 全部合并到 parent 函数中.
        算法: 按地址从小到大排序 children, 遍历 children , 获取 child 开始、结束地址， 删除 child 函数， 修改 parent 结束地址为 child 结束地址。
        :param parent:int, children:list[int]
        '''
        if not children:
            return
        children.sort()
        max_end = 0
        for i, child in enumerate(children):
            info = IDAHelper.get_fun_info(child)
            print("{} get fun {} info {}".format(i, hex(child), info))
            if ida_funcs.del_func(info['start']):
                max_end = max(max_end, info['end'])
                if ida_funcs.set_func_end(parent, max_end):
                    print("[√]adjust fun {} to end {}".format(hex(parent), hex(max_end)))
                else:
                    print("[X]Failed to adjust fun {} to end {}".format(hex(parent), hex(max_end)))
                    
            else:
                print("[X-{}]failed to delete function {}".format(i, hex(info['start'])))
                break
        
        
        print("[+]merge_funcs complete.")
