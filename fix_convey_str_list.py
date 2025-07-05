'''
导入、导出 string 列表的字符串。 用于从 frida_dump 中拿到的字符串明文，拷贝到原始 so 中。 因为 dump 后的 so文件，导入表有问题。
导出功能： 把 idb 目前定义的字符串，导出到文件，每一行开头是16进制的地址，用一个空格检测，后面是字符串内容。
导入功能： 从文件中读取字符串和地址信息，写入到 idb 中的对应地址
'''

import idaapi
import ida_kernwin
import ida_bytes
import ida_nalt
import ida_strlist
import idc
import os
import ida_segment


def get_bytes(ea):
    '''
    读取c字符串直到 null
    '''
    result =  []
    while True:
        ch = idaapi.get_byte(ea)
        if ch == 0x00:
            break
        # if all_visible
        result.append(ch)
        ea +=1
    return result

def create_str(read_bytes:list):
    sb = [chr(c) for c in read_bytes]
    return "".join(sb)

def skip_null_byte(ea):
    while True:
        ch = idaapi.get_byte(ea)
        if ch  != 0x00:
            break
        ea +=1
    return ea

def save_to_file(contents,save):
    with open(save,"w") as fp:
        for l in contents:
            try:
                fp.write(l[0]+":"+l[1]) # Every item is tuple
                fp.write("\n")
            except UnicodeEncodeError as e:
                
                print("save encode error,skip ",l)
    print("Saving file at: "+save)

def make_string(ea, data):
    '''
    在 ea 处创建字符串, 删除旧的 item 
    '''
    data_len = len(data)
    if idc.del_items(ea, idc.DELIT_SIMPLE, data_len) == False:
        print("del_items failed "+ hex(ea) + " : "+ data + " len: "+str(data_len))
        return
    
    if idaapi.create_strlit(ea, 0, 0) == False:
        print("make_string failed "+ hex(ea) + " : "+ data + " len: "+str(data_len))


def is_visible(byte):
    # 可见字符的ASCII范围是从0x20到0x7E
    if byte == 0x0A or byte == 0x0D or byte == 0x09:
        return True
    return byte >= 0x20 and byte <= 0x7E

def all_visible(read_bytes):
    # 检查所有字节是否都在可见字符范围内
    return  all(is_visible(byte) for byte in read_bytes)




def convert_data(ea,size):
    for i in range(size):
        ida_bytes.create_data(ea+i, ida_bytes.byte_flag(), i, ida_netnode.BADNODE)
    print("convert ok "+hex(ea))



def retrive_all_string(start,end):
    contents = {}
    cur_ea = start
    while cur_ea < end:
        read_bytes = get_bytes(cur_ea)
        # print("read_bytes "+ hex(cur_ea) + " : "+ str(read_bytes))
        if all_visible(read_bytes):
            data = create_str(read_bytes)
            make_string(cur_ea, data)
            contents[hex(cur_ea)] = data
        cur_ea = skip_null_byte(cur_ea + len(read_bytes))
       
    return contents

def get_string(ea):
    return idaapi.get_strlit_contents(ea,idaapi.get_max_strlit_length(ea,0),0)
class StringImportExportPlugin(idaapi.plugin_t):
    flags = idaapi.PLUGIN_UNL
    comment = "String Import/Export Tool"
    help = "Import or Export strings between file and IDA database"
    wanted_name = "String Import/Export"
    # wanted_hotkey = "Alt-F8"

    def init(self):
        return idaapi.PLUGIN_OK

    def run(self, arg):
        self.show_options_dialog()
        return True

    def term(self):
        pass

    def show_options_dialog(self):
        choice = ida_kernwin.ask_buttons("Export", "Import", "Cancel", 
                                      0, "Please select operation mode:\n"
                                      "Export: Save defined strings to file\n"
                                      "Import: Load strings from file")
        
        if choice == -1:  # Cancel
            return
        elif choice == 1:  # Export
            self.export_strings()
        elif choice == 0:  # Import
            self.import_strings()

    def get_all_strings(self):
        """Get all defined strings in the database."""
        strings = []
        
        # Get all string literals
        string_count = ida_strlist.get_strlist_qty()
        for i in range(string_count):
            string_item = ida_strlist.string_info_t()
            if ida_strlist.get_strlist_item(string_item, i):
                ea = string_item.ea
                # Get the actual string
                str_type = ida_nalt.get_str_type(ea)
                if str_type is None:
                    continue
                
                try:
                    string_content = ida_bytes.get_strlit_contents(ea, string_item.length, str_type).decode('utf-8', errors='replace')
                    strings.append((ea, string_content))
                except Exception as e:
                    print(f"Error decoding string at {ea:X}: {str(e)}")
        
        return strings

    def export_strings(self):
        """Export strings to file."""
        strings = self.get_all_strings()
        
        if not strings:
            ida_kernwin.warning("No strings found in the database!")
            return
        
        # Ask for output file
        filename = ida_kernwin.ask_file(1, "*.txt", "Save strings to file")
        if not filename:
            return
        
        try:
            with open(filename, "w", encoding="utf-8") as f:
                for ea, content in strings:
                    f.write(f"{ea:X} {content}\n")
            
            ida_kernwin.info(f"Successfully exported {len(strings)} strings to {filename}")
        except Exception as e:
            ida_kernwin.warning(f"Error writing strings to file: {str(e)}")

    def import_strings(self):
        """Import strings from file and patch bytes without creating string literals."""
        # Ask for input file
        filename = ida_kernwin.ask_file(0, "*.txt", "Select file to import strings from")
        if not filename:
            return
        
        try:
            strings_imported = 0
            strings_failed = 0
            
            with open(filename, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    
                    # Parse line format: "ADDRESS STRING"
                    parts = line.split(" ", 1)
                    if len(parts) != 2:
                        print("[X] Invalid line format")
                        strings_failed += 1
                        continue
                    
                    addr_str, content = parts
                    try:
                        # Parse the hexadecimal address
                        addr = int(addr_str, 16)
                        
                        # Convert string to bytes and patch at the address
                        string_bytes = content.encode('utf-8') + b'\0'  # Add null terminator
                        if ida_bytes.patch_bytes(addr, string_bytes):
                            strings_imported += 1
                        else:
                            print(f"[X] Failed to patch bytes at {addr_str}")
                            strings_failed += 1
                    except ValueError as e:
                        print(f"[X] error : {e}")
                        strings_failed += 1
        
            # Refresh the UI
            ida_kernwin.refresh_idaview_anyway()
            
            if strings_failed > 0:
                ida_kernwin.warning(f"Imported {strings_imported} strings, {strings_failed} failed.")
            else:
                ida_kernwin.info(f"Successfully imported {strings_imported} strings.")
            
        except Exception as e:
            ida_kernwin.warning(f"Error importing strings: {str(e)}")


        try:
            data_seg = ida_segment.get_segm_by_name('.data')
            # retrive_all_string(data_seg.start_ea, data_seg.end_ea)
            result = retrive_all_string(data_seg.start_ea, data_seg.end_ea)
            print("[+]total {} strings parsed.".format(len(result.keys())))
            print("在 strings 窗口rebuild 一下， 不build的化，strings 还是搜不到的")
            
        except Exception as e:
            print("Error retrieving strings from .data segment:", e)
            

def PLUGIN_ENTRY():
    return StringImportExportPlugin()

