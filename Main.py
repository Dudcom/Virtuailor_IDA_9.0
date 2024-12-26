from __future__ import print_function
import idc
import idautils
import idaapi
import ida_ida
import ida_typeinf

try:
    idaapi.require("AddBP")
    idaapi.require("vtableAddress")
    idaapi.require("GUI")
except ModuleNotFoundError as e:
    print(f"Error importing required modules: {e}")
    raise

from vtableAddress import REGISTERS

def get_all_functions():
    for func in idautils.Functions():
        print(hex(func), idc.get_func_name(func))

def get_xref_code_to_func(func_addr):
    xrefs = idautils.XrefsTo(func_addr, 1)
    addr = {}
    for xref in xrefs:
        frm = xref.frm
        start = idc.get_func_attr(frm, idc.FUNCATTR_START)
        func_name = idc.get_func_name(start)
        addr[func_name] = [xref.iscode, start]
    return addr

def add_bp_to_virtual_calls(cur_addr, end):
    while cur_addr < end:
        if cur_addr == idc.BADADDR:
            break
        mnemonic = idc.print_insn_mnem(cur_addr)
        if mnemonic == 'call' or mnemonic == 'BLR':
            if any(reg in idc.print_operand(cur_addr, 0) for reg in REGISTERS):
                cond, bp_address = vtableAddress.write_vtable2file(cur_addr)
                if cond:
                    AddBP.add(bp_address, cond)
        cur_addr = idc.next_head(cur_addr)

def handle_struct_operations():
    struct_id = ida_typeinf.get_named_type(idaapi.cvar.idati, "struct_name", 0)
    if struct_id is not None:
        tinfo = ida_typeinf.tinfo_t()
        if tinfo.get_numbered_type(idaapi.cvar.idati, struct_id):
            print(f"Structure name: {tinfo.get_name()}")
            print(f"Size: {tinfo.get_size()} bytes")

def set_values(start, end):
    return start, end

if __name__ == '__main__':
    try:
        start_addr_range = ida_ida.inf_get_min_ea()
        end_addr_range = ida_ida.inf_get_max_ea()
        idaapi.set_script_timeout(0)

        gui = GUI.VirtuailorBasicGUI(
            set_values,
            {'start': hex(start_addr_range)[2:], 'end': hex(end_addr_range)[2:]}
        )
        gui.exec_()

        if gui.start_line.text != "banana":
            print("Virtuailor - Started")
            start = int(gui.start_line.text(), 16)
            end = int(gui.stop_line.text(), 16)
            add_bp_to_virtual_calls(start, end)
            print("Virtuailor - Finished")

        handle_struct_operations()

    except Exception as e:
        print(f"An error occurred: {e}")
