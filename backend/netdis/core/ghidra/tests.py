import pyhidra
import os
from ..models import Task, UploadedFile, Project, Function, Block, Disasm

os.environ['GHIDRA_INSTALL_DIR'] = "/Users/sasha/Desktop/ghidra_10.3.2_PUBLIC/"

def function_call_graph(program):
 calls = {}
 called_by = {}
 with pyhidra.open_program(program) as flat_api:
    from ghidra.util.task import TaskMonitor
    monitor = TaskMonitor.DUMMY
    currentProgram = flat_api.getCurrentProgram()
    funcs = currentProgram.getFunctionManager().getFunctions(True)
    i = 0
    cg = {}
    for f in funcs:
        calls = f.getCalledFunctions(monitor)
        out = []
        for callsf in calls:
            out.append(callsf.getName())
        print(f, "calls", calls)
        called_by = f.getCallingFunctions(monitor)
        ins = []
        for callingf in called_by:
            ins.append(callingf.getName())
        print(f, "is called by", called_by)
        cg[f.getName()] = {
            "in": ins,
            "out": out
        }

    return cg

def full_disasm(program, proj_obj):
    with pyhidra.open_program(program) as flat_api:
        from ghidra.util.task import TaskMonitor
        import ghidra.program.model.block as blockmodel
        monitor = TaskMonitor.DUMMY
        currentProgram = flat_api.getCurrentProgram()
        funcs = currentProgram.getFunctionManager().getFunctions(True)
        for f in funcs:
            function_obj = Function(project=proj_obj,name=f.getName(), addr=f.getEntryPoint())
            function_obj.save()
            print(f)
            code_block_model = blockmodel.BasicBlockModel(currentProgram)
            blocks = code_block_model.getCodeBlocksContaining(f.body, monitor)
            for block in blocks:
                block_obj = Block(function = function_obj, addr=block.minAddress)
                block_obj.save()
                instruction = currentProgram.getListing().getInstructionAt(block.minAddress)
                while instruction and instruction.getMinAddress() < block.maxAddress:
                    #print(instruction.getMnemonicString())
                    operands = []
                    for i in range(instruction.getNumOperands()):
                        operands.append(instruction.getDefaultOperandRepresentation(i))
                    disasm_obj = Disasm(block=block_obj, op=instruction.getMnemonicString(), data=operands, addr=instruction.getMinAddress())
                    disasm_obj.save()
                    instruction = instruction.getNext()
        
#full_disasm("a.out")


