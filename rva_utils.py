# Various utilities to convert between IDA displayed addresses, and relative virtual addresses.
# 
# What is a "Relative virtual address":
# "In an image file, this is the address of an item after it is loaded into 
# memory, with the base address of the image file subtracted from it. The RVA 
# of an item almost always differs from its position within the file on 
# disk (file pointer)."
# 
# Useful to convert IDA addresses to CheatEngine's "Program.exe+0x<rva>" format for example.

# Converts a relative virtual address to an IDA address.
def rva_to_ida(ea):
    return MinEA() + ea
    
# Converts an IDA address to a relative virtual address.
def ida_to_rva(ea):
    return ea - idaapi.get_imagebase()

# Converts the cursor's position to a relative virtual address.
def screen_rva():
    return ida_to_module_offset(idaapi.get_screen_ea())

# Moves the cursor to a relative virtual address.
def rva_to_screen(ea):
    addr = module_offset_to_ida(ea)
    print(hex(addr))
    Jump(addr)