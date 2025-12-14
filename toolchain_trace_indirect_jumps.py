'''
配套脚本: toolchain_trace_indirect_jumps.py =》fix_indirect_jump.py 
生成 hook 函数中所有间接跳转指令的脚本
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
import sys
sys.path.append(sys.path[0]) # 增加当前目录的引用
from ida_helper import *
import re

class JumpInfo():
    def __init__(self, addr, regId) -> None:
        self.insn_addr = addr    # 跳转的指令地址
        self.jump_reg_id = regId # 跳转使用的寄存器id

js_fun_get_rva = '''
function find_belong_module(pointer) {
    var modules = Process.enumerateModules();
    let addr = pointer.toUInt32();
    for (let m of modules) {
        let begin = m.base.toUInt32();
        let end = m.size + begin;
        if (addr >= begin && addr <= end) {
            return pointer.sub(m.base).toString(16)
        }
    }
    return "0";
}
'''

template2 = '''
    function hook_%s() {
    Interceptor.attach(
                    base.add(%s),
                    {
                        onEnter: function (args) {
                            try{
                                send("%s," + find_belong_module( this.context['x%s']))
                            } catch(e) {
                                send("error indirect jump trace:" +e)
                            }
                        },
                        onLeave: function (retval) {
                        }
                    }
                )
    }
    hook_funs.push(hook_%s)
'''

outer_wrap2 = '''
function hook_indirect_jumps(base , size=0 ) {
    var hook_funs = [];

'''
outer_end_wrap2 = '''
    if(size == 0)
        size = hook_funs.length;
    for(var i=0;i<size;++i) {
        hook_funs[i]();
    }
}


function hook_linker() {
    var addr = Module.findGlobalExportByName("android_dlopen_ext");
    if (addr) {
        Interceptor.attach(addr,
            {
                onEnter: function (args) {
                    var pathptr = args[0];
                    this.hook = false;
                    if (pathptr !== undefined && pathptr != null) {
                        var path = ptr(pathptr).readCString();
                        if (path.indexOf("libxxx.so") > -1) {
                            console.log("[*]load lib:" + path);
                            this.hook = 1;
                        }
                    }
                },
                onLeave: function (retval) {
                    if (this.hook == 1) {
                        console.log("install hook libxxx")
                        hook_indirect_jumps(Process.findModuleByName("libxxx.so").base, 0);
                        console.log("[+]libxxx hook done");
                    }
                }
            }
        );
    }
}

hook_linker()
'''

def gen_hook_indirect_jump(jump_addrs:list):
    '''
    只需要输出间接跳转发生时 跳转的目标地址即可. 由修复脚本自行判断需要patch为 bl 还是 b 指令.
    输出的格式： insnAddr, jumpAddr1, jumpAddr2, ...
    :param  jump_addrs      JumpInfo实例的数组
    '''
    text = ''

    for info in jump_addrs:
        text += (template2 % (
            hex(info.insn_addr), # 函数名
            hex(info.insn_addr), # 函数地址
            hex(info.insn_addr), # 函数地址
            info.jump_reg_id, # 寄存器 id
            hex(info.insn_addr), # 函数名
        ))
    
    name = os.getcwd()+os.sep+"frida_indJumps_{}.js".format(time.localtime().tm_sec)
    f = open(name, "w")
    f.write(js_fun_get_rva + outer_wrap2 + text + outer_end_wrap2)
    f.close()
    print("generate to " + name)


def parse_indirect_call_reg(insn):
    '''
    解析间接跳转的寄存器编号.
    ie: BLR  X9, 返回 9
    '''
    insn = insn.lower()
    try:
        for s in insn.split(" "):
            if not s:
                continue
            if s.find("x") == 0:
                # re.findall(r'x(\d+)', s)
                return int(re.findall(r'x(\d+)', s)[0])
    except Exception as e:
        print("Error parse_indirect_call_reg for< "+ insn + " >" + e)
    return -1
    
def gen_indirect_call_hook(ea):
    '''
    获取当前函数内所有 BLR, BR 指令的地址, 生成 hook 脚本. 
    hook脚本实现: 输出当前地址, 输出间接跳转的 RVA 
    '''
    fun_info = IDAHelper.get_fun_info(ea)
    cur_ea = fun_info['start']
    end_ea = fun_info['end']
    end_ea = IDAHelper.find_next_inst_addr(cur_ea, "ret")
    jumps = []      # 保存间接跳转信息

    while cur_ea < end_ea:
        cur_insn = GetDisasm(cur_ea).lower()
        tmp_insn = cur_insn.replace(" ", "")
        reg_id = -1
        # 解析出跳转的 寄存器编号 
        if tmp_insn.find("blr") > -1:
            reg_id = parse_indirect_call_reg(cur_insn)
        elif tmp_insn.find("brx") > -1:
            reg_id = parse_indirect_call_reg(cur_insn)
        
        if reg_id != -1:
            # 添加到生成列表
            jumps.append(JumpInfo(cur_ea, reg_id))
        cur_ea = next_head(cur_ea)
    
    gen_hook_indirect_jump(jumps)

gen_indirect_call_hook(here())

