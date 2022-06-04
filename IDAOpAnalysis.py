import os, pickle
from time import time
from argparse import ArgumentParser
from typing import List
import idc
import idaapi
import idautils
import ida_pro
import ida_auto
import ida_nalt




OPND_WRITE_FLAGS = {
    0: idaapi.CF_CHG1,
    1: idaapi.CF_CHG2,
    2: idaapi.CF_CHG3,
    3: idaapi.CF_CHG4,
    4: idaapi.CF_CHG5,
    5: idaapi.CF_CHG6,
}

OPND_READ_FLAGS = {
    0: idaapi.CF_USE1,
    1: idaapi.CF_USE2,
    2: idaapi.CF_USE3,
    3: idaapi.CF_USE4,
    4: idaapi.CF_USE5,
    5: idaapi.CF_USE6,
}

def parse_operands(ea, debug:bool) -> List[list]:
    insn = idautils.DecodeInstruction(ea)
    result = []

    # The features are needed for operand flags.
    feature = insn.get_canon_feature()

    for op in insn.ops:
        # You always get 6 operands. Some of them are set to `o_void` to indicate
        # that they are not used.
        if op.type == idaapi.o_void:
            break

        '''get operand value (sort of operand id)
            Note: different-type operands can have the same id. E.g., eax has id of 5, and the imm 5 also has id of 5 
            @return: value
            operand is an immediate value  => immediate value
            operand has a displacement     => displacement
            operand is a direct memory ref => memory address
            operand is a register          => register number
            operand is a register phrase   => phrase number
            otherwise                      => -1
        '''
        op_id = idc.get_operand_value(ea,op.n)

        # # There are 3 types of memory references in IDA. We want all 3.
        # is_mem = op.type in (idaapi.o_mem, idaapi.o_phrase, idaapi.o_displ)
        # if not is_mem:
        #     # Operand does not access memory.
        #     continue

        # Extract per-operand read/write status from the feature.
        is_write = feature & OPND_WRITE_FLAGS[op.n]
        is_read = feature & OPND_READ_FLAGS[op.n]


        
        result.append([op.type,op_id,is_read,is_write])
        
        if debug:
            action = '{}'.format('/'.join(filter(bool, ('read' if is_read else None, 'write' if is_write else None))))
            stringToPrint = f"Function <{idc.get_func_name(ea)}> Insn <{idc.GetDisasm(ea).split(';')[0]}> Operand[{op.n}] Type [{op.type}] ID[{op_id}] <{idc.print_operand(ea, op.n)}> : {action}"
            print(stringToPrint)

    return result

def main(output_dir:str, debug:bool = True) -> None:
    os.makedirs(output_dir, exist_ok=True)

    insn_and_opinfo = [] # List[list]

    textStartEA = 0
    textEndEA = 0
    for seg in idautils.Segments():
        if (idc.get_segm_name(seg)==".text"):
            textStartEA = idc.get_segm_start(seg)
            textEndEA = idc.get_segm_end(seg)
            break
    
    for func in idautils.Functions(textStartEA, textEndEA):
        # Ignore Library Code
        flags = idc.get_func_attr(func, idc.FUNCATTR_FLAGS)
        if flags & idc.FUNC_LIB:
            if debug:
                print(hex(func), "FUNC_LIB", idc.get_func_name(func))
            continue
        start_time = time()
        for insn in idautils.FuncItems(func):
            # print(hex(insn))
            disasm = idc.GetDisasm(insn).split(';')[0]
            op_info = parse_operands(insn, debug)
            insn_and_opinfo.append([hex(insn),disasm,op_info])
        end_time = time()
        print('Running for {} seconds.'.format(end_time-start_time))
    
    with open(os.path.join(output_dir, f'{ida_nalt.get_root_filename()}.pkl'), 'wb') as f:
        pickle.dump(insn_and_opinfo, f)    
    
    
    #print(op)
    #print(hex(op.addr))
    #print([x for x in DataRefsFrom(op.addr)])


if __name__ == '__main__':
    if len(idc.ARGV) < 2:
        print('\n\nDemo of Operand Analysis with IDA Pro')
        print('\tIter through all .text functions and instructions to parse operands')
        print('\tExtract per-operand read/write status and the operand id.')
        print('\tUsage: /path/to/ida -A -Lida.log -S"{} -o output_dir" /path/to/binary\n\n'.format(idc.ARGV[0]))
        ida_pro.qexit(1)

    parser = ArgumentParser(description="IDAPython script for generating dataflow graph of each function in the given binary")
    parser.add_argument("-o", "--output_dir", help="Output dir", default='./outputs', nargs='?')
    args = parser.parse_args()

    ida_auto.auto_wait()
    
    main(args.output_dir, debug=False)
    
    ida_pro.qexit(0)
