import pyhidra
from ..models import Task, UploadedFile, Project, Function, Block, Disasm, CFGAnalysisResult, FileUploadResult
from django.contrib.contenttypes.models import ContentType
from celery import shared_task
import base64
import jpype
import logging

logger = logging.getLogger(__name__)

# This is for local dev
# os.environ['GHIDRA_INSTALL_DIR'] = "/Users/sasha/Desktop/ghidra_10.3.2_PUBLIC/"

@shared_task()
def ghidra_get_loaders(program):
    print("THIS SHOULDNT HAVE A LOAD SPEC ISSUE...")
    try:
        with pyhidra.open_program(program, analyze=False,language="x86:LE:64:default", loader="ghidra.app.util.opinion.BinaryLoader") as flat_api:
            from ghidra.app.util.opinion import LoaderService
            from ghidra.app.util.bin import FileByteProvider
            from java.nio.file import AccessMode
            from java.io import File
            byte_provider = FileByteProvider(File(program), None, AccessMode.READ)
            load_specs = LoaderService.getAllSupportedLoadSpecs(byte_provider)
            loaders = {}
            for loader in load_specs:
                loaders[loader.getName()] = loader.toString().split('@')[0]
                logger.debug(f"LOADER CLASS: {loader.toString()} LOADER NAME: {loader.getName()}")
                
            from ghidra.program.util import DefaultLanguageService
            language_service = DefaultLanguageService.getLanguageService()
            language_descs = language_service.getLanguageDescriptions(False)
            langs = {}
            for lang in language_descs:
                langs[lang.getLanguageID().getIdAsString()] = lang.getDescription()
            return [loaders, langs]
    except Exception as e:
        return {"error": e.toString()}

@shared_task()
def ghidra_get_strings(program):
    try:
        with pyhidra.open_program(program) as flat_api:
            currentProgram = flat_api.getCurrentProgram()
            memory = currentProgram.getMemory()
            strings = flat_api.findStrings(None, 4, 1, True, True)
            json_strings = {}
            for string in strings:
                current_string = string.getString(memory)
                json_strings[string.getAddress().toString()] = repr(current_string)
            return json_strings          
    except Exception as e:
        return {"error": e.toString()}

@shared_task()
def ghidra_get_rawhex(program, address, length):
    print(f"PROGRAM: {program} ADDRESS: {address} LENGTH: {length}")
    try:
        with pyhidra.open_program(program) as flat_api:
            from ghidra.program.model.address import Address
            currentProgram = flat_api.getCurrentProgram()
            
            address_factory = currentProgram.getAddressFactory()
            address = address_factory.getAddress(str(address))
            memory = currentProgram.getMemory()
            valid_lengths = [1, 2, 4, 8, 16, 32, 64, 128, 512]
            if length not in valid_lengths:
                return {"error": "Invalid size"}
            if memory.contains(address):
                byte_array = {}
                for byte in range(length):
                    logger.debug(f"At address: {str(address)}")
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
def ghidra_full_disassembly(task_id, program, file_id, loader, language):
    logger.debug(f"DOING LANGUAGE: '{language}'")
    task = Task.objects.get(pk=task_id)
    task.status = 'PROCESSING'
    task.save()
    
    kwargs = {}
    try:
        if language is not None and language.upper() != "NONE":
            kwargs['language'] = language
        if loader is not None and loader.upper() != "NONE":
            kwargs['loader'] = loader
    except Exception as e:
        logger.debug(f"Error setting up kwargs: {str(e)}")
    
    logger.debug(f"Using kwargs: {kwargs}")
    
    try:
        with pyhidra.open_program(program, **kwargs) as flat_api:
            from ghidra.util.task import TaskMonitor
            import ghidra.program.model.block as blockmodel
            monitor = TaskMonitor.DUMMY
            currentProgram = flat_api.getCurrentProgram()
            ghidra_functions = currentProgram.getFunctionManager().getFunctions(True)
            image_base = currentProgram.getImageBase().toString()
            logger.debug(f"Starting full disasm. IMAGE BASE: {image_base}")
            file = UploadedFile.objects.get(pk=file_id)
            file.image_base = image_base
            file.save()
            for f in ghidra_functions:
                print(f)
                file = UploadedFile.objects.get(pk = file_id)
                function_obj = Function(file=file,name=f.getName(), addr=f.getEntryPoint())
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
        error_message = str(e)
        logger.error(f"Error in ghidra_full_disassembly: {error_message}")
        return {"error": error_message}