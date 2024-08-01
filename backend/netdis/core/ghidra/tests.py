import pyhidra
import os
from ..models import Task, UploadedFile, Project, Function, Block, Disasm, CFGAnalysisResult, FileUploadResult
from django.contrib.contenttypes.models import ContentType
from celery import shared_task

#os.environ['GHIDRA_INSTALL_DIR'] = "/Users/sasha/Desktop/ghidra_10.3.2_PUBLIC/"

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

# My god..

@shared_task()
def ghidra_function_cfg(program, func_id):
    with pyhidra.open_program(program) as flat_api:
        from ghidra.util.task import TaskMonitor
        import ghidra.program.model.block as blockmodel
        monitor = TaskMonitor.DUMMY
        currentProgram = flat_api.getCurrentProgram()
        if Function.objects.get(id=func_id):
            func = Function.objects.get(id=func_id)
            func_address = currentProgram.getAddressFactory().getAddress(func.addr)
            f = currentProgram.getFunctionManager().getFunctionAt(func_address)
            code_block_model = blockmodel.BasicBlockModel(currentProgram)
            blocks = code_block_model.getCodeBlocksContaining(f.body, monitor)
            for block in blocks:
                if Block.objects.filter(addr=block.minAddress).exists():
                    block_obj = Block.objects.get(addr=block.minAddress)
                else:
                    block_obj = Block(function = func, addr=block.minAddress)
                    block_obj.save()
                print(f"BLOCK id {block_obj.id} : {block_obj.addr}")

                srcs = code_block_model.getSources(block, monitor)
                dsts = code_block_model.getDestinations(block, monitor)
                while srcs.hasNext():
                    src = srcs.next().getSourceBlock()
                    if Block.objects.filter(addr=src.minAddress).exists():
                        src_obj = Block.objects.get(addr=src.minAddress)
                        block_obj.src.add(src_obj)
                    else:
                        src_obj = Block(function = func, addr=src.minAddress)
                        src_obj.save()
                        block_obj.src.add(src_obj)
                    print(f"SRC id {src_obj.id} : {src_obj.addr}")
                while dsts.hasNext():
                    dst = dsts.next().getDestinationBlock()
                    if Block.objects.filter(addr=dst.minAddress).exists():
                        dst_obj = Block.objects.get(addr=dst.minAddress)
                        block_obj.dst.add(dst_obj)
                    else:
                        dst_obj = Block(function = func, addr=dst.minAddress)
                        dst_obj.save()
                        block_obj.dst.add(dst_obj)  
                    print(f"DST id {dst_obj.id} : {dst_obj.addr}")
    
            # Now return the json object!
            blocks = Block.objects.filter(function=func).all()
            nodes = [{"id": block.id} for block in blocks]
            edges = []
            for block in blocks:
                for dst in block.dst.all():
                    edges.append({"src": block.id, "dst": dst.id})
                    
            cfg_result = {"nodes": nodes, "edges": edges}
    return cfg_result


@shared_task()
def ghidra_full_disassembly(program, proj_obj_id):
    with pyhidra.open_program(program) as flat_api:
        from ghidra.util.task import TaskMonitor
        import ghidra.program.model.block as blockmodel
        monitor = TaskMonitor.DUMMY
        currentProgram = flat_api.getCurrentProgram()
        funcs = currentProgram.getFunctionManager().getFunctions(True)
        for f in funcs:
            project = Project.objects.get(pk = proj_obj_id)
            function_obj = Function(project=project,name=f.getName(), addr=f.getEntryPoint())
            function_obj.save()
            code_block_model = blockmodel.BasicBlockModel(currentProgram)
            blocks = code_block_model.getCodeBlocksContaining(f.body, monitor)

            for block in blocks:
                block_obj = Block(function = function_obj, addr=block.minAddress)
                block_obj.save()
                
                instruction = currentProgram.getListing().getInstructionAt(block.minAddress)
                while instruction and instruction.getMinAddress() < block.maxAddress:
                    operands = []
                    for i in range(instruction.getNumOperands()):
                        operands.append(instruction.getDefaultOperandRepresentation(i))
                    disasm_obj = Disasm(block=block_obj, op=instruction.getMnemonicString(), data=operands, addr=instruction.getMinAddress())
                    disasm_obj.save()
                    instruction = instruction.getNext()
