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



## Fix indirect jumps / function calls

### fix_blr_2_nop.py

Purpose:
- Quickly replace indirect branch/call instructions (e.g. BR/BLR on ARM) with NOPs inside a function and merge basic blocks to produce more linear, readable pseudocode.

When to use:
- Quick triage to reveal call sites and data accesses when exact branching is not required.

Usage (IDA):
- Open the target binary in IDA and navigate to the function entry.
- Run fix_blr_2_nop.py as an IDA Python script. The script scans the function, locates indirect branch/call opcodes, patches them to NOP, and attempts to merge the following basic blocks.

Output:
- IDB modifications (patched instructions) and improved Hex-Rays pseudocode after refreshing the view.

Notes:
- Backup your IDB before running the script.
- Prefer generating a patch list first if you want to review changes before applying.


---

### toolchain_trace_indirect_jumps.py

Purpose:
- Auto-generate a Frida hooking script (or a set of hooks) from static analysis results to capture runtime targets for indirect jumps/calls.

Workflow overview:
1. Use IDA to scan and collect addresses of indirect branch/call instructions (the script can help produce this list).
2. Run toolchain_trace_indirect_jumps.py to produce a Frida script that attaches hooks to those addresses and logs resolved targets as module-relative offsets.
3. Inject the generated Frida script into the target process (spawn/resume or attach) and exercise the program paths.
4. Save the runtime log (structured text or CSV) for later patching.



Notes:
- Use module-relative offsets so logs remain valid if the module base changes between runs.
- Combine with fix_blr_2_nop.py (run as preprocessing) when the function is noisy.

---

### fix_indirect_jump.py

Purpose:
- Parse the runtime logs produced by toolchain_trace_indirect_jumps.py (or manually collected Frida output) and apply patches in IDA to convert indirect transfers into direct branches/calls or annotate the binary with resolved targets.

Usage (IDA):
- Prepare a  log file from Frid .
- Open the IDB in IDA and run fix_indirect_jump.py with the path to the log file.
- The script will locate the recorded instruction addresses, compute absolute targets based on module base (or use module-relative offsets), and patch instructions accordingly. It may also add comments/renames for visibility.

Safety and verification:
- Scripts typically support a dry-run mode to only print planned changes without applying them — use this first.
- Keep backups of IDB/ELF. After patching, manually inspect and re-run the decompiler to verify correctness.

---

# 要你命3000

“要你命 3000”这个名字来源于周星驰电影《国产 007》中达闻西研发的终极必杀武器。本项目旨在为 Android 逆向工程中遇到的各种代码混淆手段提供破解方法或思路，主要通过 IDA 的 Python 脚本插件实现。

 ![](README.assets/909b0d9a99f76e2a3a25e61ad71672f9.jpg)





# 功能概览

## 修复间接跳转/函数调用

### fix_blr_2_nop.py



目的：
- 在函数内把间接跳转/调用指令（如 ARM 的 BR/BLR）替换为 NOP，并合并基本块，以快速得到可读的伪代码。

适用场景：
- 快速定位函数调用与数据访问，不要求保留精确的分支语义时使用。

使用方法（IDA）：
- 在 IDA 中打开目标，定位到函数入口；
- 以 IDA Python 方式运行 fix_blr_2_nop.py，脚本会扫描函数内的间接转移指令并打成 NOP，随后尝试合并基本块。

产出：
- 修改后的 IDB（被 patch 的指令）和刷新后的 Hex-Rays 伪代码。

注意：
- 运行前请备份 IDB；
- 如果希望先 review 补丁，可先让脚本输出补丁清单再应用。

---



### toolchain_trace_indirect_jumps.py



目的：
- 根据静态分析结果生成 Frida hook 脚本，在运行时记录间接跳转/调用的实际目标地址，方便后续将这些目标 patch 回 IDB。

工作流程：
1. 在 IDA 中扫描并收集间接跳转/调用指令地址（脚本可帮助生成地址列表）；
2. 运行 toolchain_trace_indirect_jumps.py 生成用于 Frida 的 hook 脚本，该脚本会在运行时记录目标地址并建议以模块相对偏移输出；
3. 将生成脚本注入目标进程（spawn/resume 或 attach），触发相关代码路径；
4. 保存运行日志以便后续解析与 patch。


注意：
- 使用模块相对偏移可以在模块基址变化时复用日志；
- 对噪声较多的函数，可先运行 fix_blr_2_nop.py 做预处理。

---



### fix_indirect_jump.py



目的：
- 解析由 toolchain_trace_indirect_jumps.py 生成的运行时日志（或 Frida 的人工导出），并在 IDA 中将间接跳转/调用替换为直接跳转/调用，或备注解析到的目标地址。

使用方法（IDA）：
- 将 Frida 日志保存为文件；
- 在打开的 IDB 中运行 fix_indirect_jump.py 并传入日志文件路径；
- 脚本会根据日志定位指令地址，使用模块基址还原绝对目标并 patch 指令，也可以添加注释和符号以提升可读性。

安全与验证：
- 备份 IDB/ELF。patch 后请手工检查并刷新 Hex-Rays 视图验证修复结果。

---

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























