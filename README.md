# Deadly 3000

​		The name "Deadly 3000" originates from Stephen Chow's movie Chinese 007, where it refers to the ultimate weapon developed by the character Da Wenxi. This project aims to provide methods and ideas for cracking various code obfuscation techniques encountered during Android reverse engineering, primarily through IDA Python script plugins.

  ![](README.assets/909b0d9a99f76e2a3a25e61ad71672f9.jpg)



# Features Overview

## Decrypting Encrypted Strings

### toolchain_collect_ret_insn.py

**Principle**:
This script searches for all return instructions and generates a Frida hook script to output all returned strings (including potential garbage). It helps quickly locate critical code.



### top_xref.py

**Principle**:
By analyzing the cross-references of functions, this script outputs the top N functions with the highest reference counts. Users can manually inspect these functions to locate string decryption or construction functions and hook them to output plaintext.



### toolchain_trace_dyn_dec_str.py

**Principle**:
For strings decrypted into dynamically allocated memory, this script traverses the .bss section and attempts to output strings via pointers. Combined with fix_enc_str.py, it annotates the discovered plaintext in the corresponding IDA addresses and facilitates searching through breakpoints.



### toolchain_apply_trace_dyn_dec_str.py

**Principle**:
Based on the information dumped by toolchain_trace_dyn_dec_str, this script fills the decrypted string information back into the IDB file using breakpoints and annotations.



**Trace JNI Functions**
**Principle**:
Hooks JNI functions like NewUTFString and GetStringChars to capture strings passed between Java and C.





### fix_convey_str_list.py

**Principle**:
Exports decrypted strings from a Frida-dumped .so file and applies them to another IDB file that has not been decrypted.






# 要你命3000

“要你命 3000”这个名字来源于周星驰电影《国产 007》中达闻西研发的终极必杀武器。本项目旨在为 Android 逆向工程中遇到的各种代码混淆手段提供破解方法或思路，主要通过 IDA 的 Python 脚本插件实现。

 ![](README.assets/909b0d9a99f76e2a3a25e61ad71672f9.jpg)






# 功能概览


## 去除字符串加密

### toolchain_collect_ret_insn.py 

**原理：**		

​		该脚本会搜索所有的返回指令，并生成 Frida hook 脚本，输出所有返回的字符串（包括可能的乱码）。此方法便于快速定位关键代码。







### top_xref.py 

**原理：**		

​		通过分析函数的交叉引用数量，脚本从高到低输出调用次数最多的 N 个函数。用户可以逐个排查，定位字符串解密函数或构造函数，并进一步 hook 输出明文。





### toolchain_trace_dyn_dec_str.py

**原理：**

​		针对解密到动态分配内存中的字符串，脚本遍历 .bss 节区，尝试以指针方式输出字符串。结合 toolchain_apply_trace_dyn_dec_str.py，将找到的明文备注到 IDA 对应地址，并通过断点方式方便搜索。



### toolchain_apply_trace_dyn_dec_str.py

原理：

​		基于 toolchain_trace_dyn_dec_str 脚本 dump 的信息，将解密的字符串信息回填到 IDB 文件中，通过断点和备注的方式实现。



### trace JNI的函数

**原理：**

​		通过 hook NewUTFString、GetStringChars 等 JNI 函数，获取 Java 和 C 之间传递的字符串。





### fix_convey_str_list.py

原理：

​		将 Frida dump 出来的解密字符串导出，并应用到另一个未解密的 IDB 文件中。























