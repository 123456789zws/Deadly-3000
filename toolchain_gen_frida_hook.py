'''
生成 frida hook 脚本
'''
import sys
sys.path.append(sys.path[0]) # 增加当前目录的引用
from ida_helper import *


template = '''
    function hook_%s() {
    Interceptor.attach(
                    base.add(%s),
                    {
                        onEnter: function (args) {
                            //console.log("%s is called");
                        },
                        onLeave: function (retval) {
                            try{
                                console.log("%s return str:"+retval.readCString())
                            }catch (error) {

                            }
                        }
                    }
                )
    }
    hook_funs.push(hook_%s)
'''
outer_wrap = '''
function hook_possible_cipher(base, size = 0) {
    var hook_funs = [];

'''
outer_end_wrap = '''
    if(size == 0)
        size = hook_funs.length;
    for(var i=0;i<size;++i) {
        hook_funs[i]();
    }
}

// 调用 hook_possible_cipher(base, size) 来执行所有的 hook 函数
// 这里需要手动去 查找模块的 base 地址
// 例如: base = Module.findBaseAddress("libc.so")
hook_possible_cipher(base, 0);
'''

def gen_script(funcs):
    text = ''
    # funcs = IDAHelper.get_all_func()
    # funcs = funcs[:10]
    for addr in funcs:
        # text += template.format(offset=addr)
        text += (template % (hex(addr), hex(addr), hex(addr), hex(addr), hex(addr)))
    
    return outer_wrap + text + outer_end_wrap



