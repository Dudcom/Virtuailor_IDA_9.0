from __future__ import print_function
import idc
import idautils
import idaapi
import ida_ida
import ida_typeinf
import sys
import os

idaapi.require("AddBP")

REGISTERS = ['eax', 'ebx', 'ecx', 'edx', 'rax', 'rbx', 'rcx', 'rdx', 'rdi', 'rsi', 'r8', 'r9', 'r10', 'r15', 'X0', 'X1', 'X2', 'X3', 'X4',
             'X5', 'X6', 'X7', 'X8', 'X9', 'X10', 'X11', 'X12', 'X13', 'X14', 'X15', 'X16', 'X17', 'X18', 'X19', 'X20',
             'X21', 'X22', 'X23', 'X24', 'X25', 'X26', 'X27', 'X28', 'X29', 'X30', 'X31']


def get_processor_architecture():
    """
    Detect processor architecture and bitness.
    """
    arch = "Intel"
    proc_name = ida_ida.inf_get_procname()  # Replacement for procname
    if proc_name == "ARM":
        arch = "ARM"
    if ida_ida.inf_is_64bit():  # Replacement for is_64bit()
        return arch, True
    elif ida_ida.inf_is_32bit():  # Replacement for is_32bit()
        return arch, False
    else:
        return "Error", False


def get_local_var_value_64(loc_var_name):
    """
    Retrieve the value of a local variable for 64-bit architectures.
    """
    frame_id = idc.get_frame_id(idc.here())
    if frame_id == idc.BADADDR:
        print("Error: Unable to retrieve frame.")
        return None
    frame = ida_typeinf.tinfo_t()
    if not frame.get_numbered_type(idaapi.cvar.idati, frame_id):
        print("Error: Unable to load frame structure.")
        return None
    member = frame.get_udm_by_name(loc_var_name)
    if not member:
        print(f"Error: Local variable '{loc_var_name}' not found.")
        return None
    loc_var_start = member.offset
    loc_var_ea = loc_var_start + idc.get_reg_value("RSP")
    loc_var_value = idc.read_dbg_qword(loc_var_ea)
    return loc_var_value


def get_arch_dct():
    """
    Define architecture-specific details for ARM and Intel.
    """
    arch, is_64 = get_processor_architecture()
    if arch != "Error" or (arch == "ARM" and not is_64):
        dct_arch = {}
        if arch == "ARM":
            dct_arch["opcode"] = "LDR"
            dct_arch["separator"] = ","
            dct_arch["val_offset"] = 2
        if arch == "Intel":
            dct_arch["opcode"] = "mov"
            dct_arch["separator"] = "+"
            dct_arch["val_offset"] = 1
        return dct_arch
    else:
        print("Error: Unsupported architecture. Supported architectures are Intel x64/x32 and ARM x64.")
        return -1


def get_con2_var_or_num(i_cnt, cur_addr):
    """
    Get information about virtual calls in a function.
    """
    start_addr = idc.get_func_attr(cur_addr, idc.FUNCATTR_START)
    dct_arch = get_arch_dct()
    if dct_arch == -1:
        return 'Unsupported Architecture', "-1", cur_addr

    while cur_addr >= start_addr:
        if idc.print_insn_mnem(cur_addr)[:3] == dct_arch["opcode"] and idc.print_operand(cur_addr, 0) == i_cnt:
            opnd2 = idc.print_operand(cur_addr, 1)
            place = opnd2.find(dct_arch["separator"])
            if place != -1:
                register = opnd2[opnd2.find('[') + 1: place]
                offset = opnd2[place + dct_arch["val_offset"]: opnd2.find(']')]
                return register, offset, cur_addr
            else:
                offset = "0"
                register = opnd2[opnd2.find('[') + 1: opnd2.find(']')]
                return register, offset, cur_addr
        elif idc.print_insn_mnem(cur_addr)[:4] == "call":
            intr_func_name = idc.print_operand(cur_addr, 0)
            if "guard_check_icall_fptr" not in intr_func_name:
                print(f"Warning: Virtual call might be in another function near {hex(cur_addr)}.")
                cur_addr = start_addr
        cur_addr = idc.prev_head(cur_addr)
    return "Out of function", "-1", cur_addr


def get_bp_condition(start_addr, register_vtable, offset):
    """
    Generate breakpoint condition script for the given architecture.
    """
    arch, is_64 = get_processor_architecture()
    file_name = "BPCond.py" if arch == "Intel" else "BPCondAarch64.py"
    condition_file = os.path.join(os.path.dirname(os.path.abspath(sys.argv[0])), file_name)

    if arch != "Error" or (arch == "ARM" and not is_64):
        with open(condition_file, 'r') as f1:
            bp_cond_text = f1.read()
        bp_cond_text = bp_cond_text.replace("<<<start_addr>>>", str(start_addr))
        bp_cond_text = bp_cond_text.replace("<<<register_vtable>>>", register_vtable)
        bp_cond_text = bp_cond_text.replace("<<<offset>>>", offset)
        return bp_cond_text
    return "# Error in BP condition"


def write_vtable2file(start_addr):
    """
    Write the vtable information to a file and return the breakpoint condition and address.
    """
    raw_opnd = idc.print_operand(start_addr, 0)
    reg = next((reg for reg in REGISTERS if reg in raw_opnd), None)
    opnd = get_con2_var_or_num(reg, start_addr)
    reg_vtable = opnd[0]
    offset = opnd[1]
    bp_address = opnd[2]
    set_bp = True
    cond = ""
    try:
        arch_dct = get_arch_dct()
        plus_index = raw_opnd.find(arch_dct["separator"])
        if plus_index != -1:
            call_offset = raw_opnd[plus_index + 1:raw_opnd.find(']')]
            if 'h' in call_offset:
                call_offset = int(call_offset[:call_offset.find('h')], 16)
        if 'h' in offset:
            offset = str(int(offset[:offset.find('h')], 16))
    except ValueError:
        set_bp = False
    finally:
        if set_bp:
            if reg_vtable in REGISTERS:
                cond = get_bp_condition(start_addr, reg_vtable, offset)
    return cond, bp_address


if __name__ == "__main__":
    try:
        start_addr_range = ida_ida.inf_get_min_ea()
        end_addr_range = ida_ida.inf_get_max_ea()
        arch, is_64 = get_processor_architecture()
        print(f"Architecture: {arch}, 64-bit: {is_64}")
        print(f"Address range: {hex(start_addr_range)} - {hex(end_addr_range)}")
    except Exception as e:
        print(f"An error occurred: {e}")
