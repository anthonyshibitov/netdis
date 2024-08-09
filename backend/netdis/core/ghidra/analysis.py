import pyhidra
from ..models import Task, UploadedFile, Project, Function, Block, Disasm, CFGAnalysisResult, FileUploadResult
from django.contrib.contenttypes.models import ContentType
from celery import shared_task

# This is for local dev
# os.environ['GHIDRA_INSTALL_DIR'] = "/Users/sasha/Desktop/ghidra_10.3.2_PUBLIC/"

@shared_task()
def ghidra_decompile_func(program, func_id):
    try:
        with pyhidra.open_program(program) as flat_api:
            from ghidra.app.decompiler import DecompInterface
            from ghidra.util.task import ConsoleTaskMonitor
            print("DECOMPILE FUNC")
            currentProgram = flat_api.getCurrentProgram()
            print("CURRENT PROGRAM:", currentProgram)
            
            func = Function.objects.get(id=func_id)
            print("FUNC OBJ:", func)
            
            func_address = currentProgram.getAddressFactory().getAddress(func.addr)
            print("FUNC_ADDRESS:", func_address)
            
            function = currentProgram.getFunctionManager().getFunctionAt(func_address)
            print("FUNCTION:", function)
            
            # Using DecompInterface for more control
            decompiler = DecompInterface()
            decompiler.openProgram(currentProgram)
            task_monitor = ConsoleTaskMonitor()
            decomp_result = decompiler.decompileFunction(function, 30, task_monitor)
            
            print("RESULTS:", decomp_result)

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
                func = Function.objects.get(id=func_id)
                func_address = currentProgram.getAddressFactory().getAddress(func.addr)
                f = currentProgram.getFunctionManager().getFunctionAt(func_address)
                code_block_model = blockmodel.BasicBlockModel(currentProgram)
                blocks = code_block_model.getCodeBlocksContaining(f.body, monitor)
                edges = []
                for block in blocks:
                    if Block.objects.filter(function=func, addr=block.minAddress).exists():
                        block_obj = Block.objects.get(function=func, addr=block.minAddress)
                    else:
                        block_obj = Block(function = func, addr=block.minAddress)
                        block_obj.save()
                    #print(f"BLOCK id {block_obj.id} : {block_obj.addr}")

                    srcs = code_block_model.getSources(block, monitor)
                    dsts = code_block_model.getDestinations(block, monitor)
                    while srcs.hasNext():
                        src = srcs.next().getSourceBlock()
                        if Block.objects.filter(function=func, addr=src.minAddress).exists():
                            src_obj = Block.objects.get(function=func, addr=src.minAddress)
                            block_obj.src.add(src_obj)
                        else:
                            src_obj = Block(function = func, addr=src.minAddress)
                            src_obj.save()
                            block_obj.src.add(src_obj)
                        #print(f"SRC id {src_obj.id} : {src_obj.addr}")
                    while dsts.hasNext():
                        dst_edge = dsts.next()
                        dst = dst_edge.getDestinationBlock()
                        # if dst_edge.getFlowType().isCall():
                        #     continue
                        if Block.objects.filter(function=func, addr=dst.minAddress).exists():
                            
                            dst_obj = Block.objects.get(function=func, addr=dst.minAddress)
                            block_obj.dst.add(dst_obj)
                        else:
                            dst_obj = Block(function = func, addr=dst.minAddress)
                            dst_obj.save()
                            block_obj.dst.add(dst_obj)  
                        edge_type = ""
                        # print(f"FLOW TYPE FROM {block_obj.id} to {dst_obj.id}")
                        # print(dst_edge.getFlowType())
                        if(dst_edge.getFlowType().isConditional()):
                            edge_type = "conditional"
                        if(dst_edge.getFlowType().isUnConditional()):
                            edge_type = "unconditional"
                        edges.append({"src": block_obj.id, "dst": dst_obj.id, "type": edge_type})
        
                # Now return the json object!
                blocks = Block.objects.filter(function=func).all()
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
            funcs = currentProgram.getFunctionManager().getFunctions(True)
            for f in funcs:
                project = Project.objects.get(pk = proj_obj_id)
                function_obj = Function(project=project,name=f.getName(), addr=f.getEntryPoint())
                function_obj.save()
                code_block_model = blockmodel.BasicBlockModel(currentProgram)
                blocks = code_block_model.getCodeBlocksContaining(f.body, monitor)

                #Here is where we need to address the call fallthrough issue
                for block in blocks:
                    block_obj = Block(function = function_obj, addr=block.minAddress)
                    block_obj.save()
                    
                    instruction = currentProgram.getListing().getInstructionAt(block.minAddress)
                    while instruction and instruction.getMinAddress() <= block.maxAddress:
                        # print("instruction min address")
                        # print(instruction.getMinAddress())
                        # print("block max address")
                        # print(block.maxAddress)
                        operands = ''
                        for i in range(instruction.getNumOperands()):
                            operands += instruction.getDefaultOperandRepresentation(i)
                            operands += ', '
                        operands = operands[:-2]
                        disasm_obj = Disasm(block=block_obj, op=instruction.getMnemonicString(), data=operands, addr=instruction.getMinAddress())
                        disasm_obj.save()
                        instruction = instruction.getNext()
    except Exception as e:
        print(e)
        print(e.__dir__())
        return {"error": e.toString()}