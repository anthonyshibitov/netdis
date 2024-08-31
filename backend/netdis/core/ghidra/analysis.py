import pyhidra
from ..models import Task, UploadedFile, Project, Function, Block, Disasm, CFGAnalysisResult, FileUploadResult
from django.contrib.contenttypes.models import ContentType
from celery import shared_task
import base64

# This is for local dev
# os.environ['GHIDRA_INSTALL_DIR'] = "/Users/sasha/Desktop/ghidra_10.3.2_PUBLIC/"

@shared_task()
def ghidra_get_rawhex(program, address, length):
    try:
        with pyhidra.open_program(program) as flat_api:
            from ghidra.program.model.address import Address
            currentProgram = flat_api.getCurrentProgram()
            
            address_factory = currentProgram.getAddressFactory()
            address = address_factory.getAddress(address)
            memory = currentProgram.getMemory()
            valid_lengths = [1, 2, 4, 8, 16, 32, 64, 128]
            if length not in valid_lengths:
                return {"error": "Invalid size"}
            if memory.contains(address):
                byte_array = {}
                for byte in range(length):
                    try:
                        byte_array[str(address)] = format(memory.getByte(address) & 0xFF, '02x')
                    except:
                        byte_array[str(address)] = "??"
                    address = address.add(1)
                return byte_array
            else:
                return {"error": "Invalid address"}
    except Exception as e:
        return {"error": e.toString()}

@shared_task()
def ghidra_decompile_func(program, func_id):
    try:
        with pyhidra.open_program(program) as flat_api:
            from ghidra.app.decompiler import DecompInterface
            from ghidra.util.task import ConsoleTaskMonitor
            currentProgram = flat_api.getCurrentProgram()
            function_obj = Function.objects.get(id=func_id)
            function_address = currentProgram.getAddressFactory().getAddress(function_obj.addr)
            ghidra_function = currentProgram.getFunctionManager().getFunctionAt(function_address)
            decompiler = DecompInterface()
            decompiler.openProgram(currentProgram)
            task_monitor = ConsoleTaskMonitor()
            decomp_result = decompiler.decompileFunction(ghidra_function, 30, task_monitor)
            if decomp_result.decompileCompleted():
                decompiled_code = decomp_result.getDecompiledFunction().getC()
                return decompiled_code
            else:
                error_message = decomp_result.getErrorMessage()
                return {"error": error_message}
    except Exception as e:
        return {"error": e.toString()}

@shared_task()
def ghidra_function_cfg(program, func_id):
    try:
        with pyhidra.open_program(program) as flat_api:
            from ghidra.util.task import TaskMonitor
            import ghidra.program.model.block as blockmodel
            monitor = TaskMonitor.DUMMY
            currentProgram = flat_api.getCurrentProgram()
            if Function.objects.get(id=func_id):
                function_obj = Function.objects.get(id=func_id)
                func_address = currentProgram.getAddressFactory().getAddress(function_obj.addr)
                ghidra_function = currentProgram.getFunctionManager().getFunctionAt(func_address)
                code_block_model = blockmodel.BasicBlockModel(currentProgram)
                blocks = code_block_model.getCodeBlocksContaining(ghidra_function.body, monitor)
                edges = []
                for block in blocks:
                    if Block.objects.filter(function=function_obj, addr=block.minAddress).exists():
                        block_obj = Block.objects.get(function=function_obj, addr=block.minAddress)
                    else:
                        block_obj = Block(function = function_obj, addr=block.minAddress)
                        block_obj.save()
                    srcs = code_block_model.getSources(block, monitor)
                    dsts = code_block_model.getDestinations(block, monitor)
                    while srcs.hasNext():
                        src = srcs.next().getSourceBlock()
                        if Block.objects.filter(function=function_obj, addr=src.minAddress).exists():
                            src_obj = Block.objects.get(function=function_obj, addr=src.minAddress)
                            block_obj.src.add(src_obj)
                        else:
                            src_obj = Block(function = function_obj, addr=src.minAddress)
                            src_obj.save()
                            block_obj.src.add(src_obj)
                    while dsts.hasNext():
                        dst_edge = dsts.next()
                        dst = dst_edge.getDestinationBlock()
                        if Block.objects.filter(function=function_obj, addr=dst.minAddress).exists():
                            dst_obj = Block.objects.get(function=function_obj, addr=dst.minAddress)
                            block_obj.dst.add(dst_obj)
                        else:
                            dst_obj = Block(function = function_obj, addr=dst.minAddress)
                            dst_obj.save()
                            block_obj.dst.add(dst_obj)  
                        edge_type = ""
                        if(dst_edge.getFlowType().isConditional()):
                            edge_type = "conditional"
                        if(dst_edge.getFlowType().isUnConditional()):
                            edge_type = "unconditional"
                        edges.append({"src": block_obj.id, "dst": dst_obj.id, "type": edge_type})
        
                # Now return the json object!
                blocks = Block.objects.filter(function=function_obj).all()
                nodes = [{"id": block.id} for block in blocks]
                        
                cfg_result = {"nodes": nodes, "edges": edges}
    except Exception as e:
        return {"error": e.toString()}
    return cfg_result

@shared_task()
def ghidra_full_disassembly(program, proj_obj_id):
    try:
        with pyhidra.open_program(program) as flat_api:
            from ghidra.util.task import TaskMonitor
            import ghidra.program.model.block as blockmodel
            monitor = TaskMonitor.DUMMY
            currentProgram = flat_api.getCurrentProgram()
            ghidra_functions = currentProgram.getFunctionManager().getFunctions(True)
            print("NOW THIS IS WHEN INTENSE PORTION STARTS!")
            for f in ghidra_functions:
                print(f)
                project = Project.objects.get(pk = proj_obj_id)
                function_obj = Function(project=project,name=f.getName(), addr=f.getEntryPoint())
                function_obj.save()
                code_block_model = blockmodel.BasicBlockModel(currentProgram)
                blocks = code_block_model.getCodeBlocksContaining(f.body, monitor)
                for block in blocks:
                    block_obj = Block(function = function_obj, addr=block.minAddress)
                    block_obj.save()
                    instruction = currentProgram.getListing().getInstructionAt(block.minAddress)
                    while instruction and instruction.getMinAddress() <= block.maxAddress:
                        operands = ''
                        for i in range(instruction.getNumOperands()):
                            operands += instruction.getDefaultOperandRepresentation(i)
                            operands += ', '
                        operands = operands[:-2]
                        disasm_obj = Disasm(block=block_obj, op=instruction.getMnemonicString(), data=operands, addr=instruction.getMinAddress())
                        disasm_obj.save()
                        instruction = instruction.getNext()
    except Exception as e:
        return {"error": e.toString()}