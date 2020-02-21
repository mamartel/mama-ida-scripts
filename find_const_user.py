# Find the next function using the specified immediate values.
# /!\ Search will start at cursor's position /!\
#
# Example (load this file and enter this in as a Python command):
# find_const_user([0x6674, 132, 0x2862])

from idautils import *
from idaapi import *
from idc import *

def find_const_user(needles):
    o_void = 0
    o_imm = 5
    
    func_index = 0
    for func in Functions(NextFunction(ScreenEA())):
        if func_index % 100 == 0:
            print "%i functions searched" % func_index
        func_index += 1
        
        func_start = GetFunctionAttr(func, FUNCATTR_START)
        func_end = GetFunctionAttr(func, FUNCATTR_END)
        if func_start == -1:
            print "Couldn't get start of function %p" % func
            continue
        if func_end == -1:
            print "Couldn't get end of function %p" % func
            continue
            
        remaining_needles = needles[:]
        for item_ea in FuncItems(func):
            for op_idx in range(6):
                op_type = GetOpType(item_ea, op_idx)
                if op_type <= 0:
                    break
                if op_type != o_imm:
                    continue
                    
                op_value = GetOperandValue(item_ea, op_idx)
                try:
                    remaining_needles.remove(op_value)
                    if len(remaining_needles) == 0:
                        print "Function found at %x" % func
                        Jump(item_ea)
                        return
                except ValueError:
                    pass
    
    print "Nothing found!"