'''
追踪由 malloc 分配内存解密的字符串.
思路:
部分app，会调用malloc动态分配内存，把字符串解密到对应 buf 中，并把这个 malloc 得到的指针，保存到 bss段。
那么思路就是，遍历 bss 段的所有指针，对其尝试进行3种字符串读取：
1.直接读取内存；
2.读取cpp string；
3.读取指针，再读取cpp string
把读取的结果和这个 bss 指针做关联，
ie:
1. native detector 采用了  antidump，无法直接dump so。 因此通过frida 附加，然后直接把整个data段输出到文件，再用 IDA 去patch
'''

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
# from keystone import *
import sys
sys.path.append(sys.path[0]) # 增加当前目录的引用
from ida_helper import *

text_begin = '''
function allPrintable(string) {
    for (var i = 0; i < string.length; i++) {
        var charCode = string.charCodeAt(i);
        if (charCode < 32 && charCode !== 9 && charCode !== 10 && charCode !== 13 || charCode > 126) {
            return false;
        }
    }
    return true;
}

function read_cpp_str3(str_addr) {
    try {
        if (str_addr.readU16() & 1) {
            // 长字符串
            return str_addr.add(Process.pointerSize * 2).readPointer().readCString()
        }
        return str_addr.add(1).readCString()
    } catch (error) {
        return "";
    }
}

/**
 * 尝试通过 几种方法读取 addr 对应的字符串
 * @param {Pointer} addr 
 */
function try_read_str(addr) {
    // 1. 直接读取字符串
    try {
        var str = addr.readCString()
        if (str != "" && allPrintable(str)) {

            return str;
        }
    } catch (error) {
    }
    try {
        str = addr.readPointer().readCString()
        if (str != "" && allPrintable(str))
            return str;
    } catch (error) {
    }
    // 2.把 addr 当做 cpp str 指针读取
    try {
        var str2 = read_cpp_str3(addr)
        if (str2 != "" && allPrintable(str2))
            return str2
    } catch (error) {
    }
    try {
        // 3.把 addr 当做 cpp str & 指针读取
        var str3 = read_cpp_str3(addr.readPointer())
        if (str3 != "" && allPrintable(str3))
            return str3
        return "";
    } catch (error) {
    }
    return "";
}
'''


text_end = '''
function dump_bss() {
    var last_str_addr = 0;
    var last_str_len = 0;
    for (var i in li) {
        var offset = li[i]
        // 确保当前输出的字符串地址范围，不在前一个字符串的范围内
        if (last_str_len > 0 && (last_str_addr + last_str_len) > offset)
            continue;
        var s = try_read_str(Process.findModuleByName("libXXX.so").base.add(offset))
        if (s != "") {
            console.log(`${offset.toString(16)} :  ${s}`)
            last_str_addr = offset;
            last_str_len = s.length;
        }
    }
}
dump_bss()
'''

def guess_is_dynamic_pointer(addr):
    '''
    猜测一个地址是否为 动态分配内存的指针.
    一个地址可能保存的信息： 普通常量数字、函数地址、一个指针、其他
    '''
    if get_qword(addr) == 0 or \
        get_qword(get_qword(addr)) == BADADDR: # 函数地址、plt 都可以二次解引用
        return True
    return False

def guess_dynamic_decrypt(addr):
    '''
    猜测一个地址是否可能在运行时 解密出字符串.
    ollvm 字符串加密的一种方式，是在运行时解密字符串回到 data段，因此对应的地址会被 adrp 指令交叉引用。 
    ADRL            X2, byte_7EB648
    '''
    try:
        xrefs = IDAHelper.get_xrefs_to(addr)
        if len(xrefs) > 0:
            for ref in xrefs:
                inst = GetDisasm(ref.frm).lower()
                if inst.find("adr") > -1:
                    return True

    except :
        pass
    return False

def is_addr_a_string(addr):
    '''
    判断当前位置是否是一个字符串.
    '''
    try:
        return get_ea_name(addr).find("a") == 0
    except :
        pass
    return False



def search_data_seg_str():
    '''
    搜索 data 段定义的可疑的字符串指针地址并返回
    '''
    begin, end = IDAHelper.get_seg_begin_end('.data')
    data_pointers  = [] # 保存可疑的指针数组

    while begin < end :
        if is_addr_a_string(begin):
            # 若当前位置已经是字符串了，那么直接跳到下一个？ 
            begin = next_head(begin)
        if guess_is_dynamic_pointer(begin):
            data_pointers.append(begin)
        elif guess_dynamic_decrypt(begin):
            data_pointers.append(begin)
        begin = next_head(begin)
    return data_pointers

def gen_trace():
    begin, end = IDAHelper.get_seg_begin_end('.bss')
    bss_pointers = []
    while begin < end :
        cur_ea =  begin
        bss_pointers.append(cur_ea)
        begin +=  8
    
    t = ''
    bss_pointers.extend(search_data_seg_str())
    for addr in bss_pointers:
        t += "{},".format(hex(addr))
    t = "var li = ["+ t +"]"

    code = text_begin + t + text_end
    name = os.getcwd()+os.sep+"frida_trace_dynDecStr_{}.js".format(time.localtime().tm_sec)
    with open(name, 'w', encoding='utf8') as fp:
        fp.write(code)
        print("output js to {}. 注意需要手动修改下 findBaseAddress 搜索的模块名".format(name))
        # print(code)

gen_trace()