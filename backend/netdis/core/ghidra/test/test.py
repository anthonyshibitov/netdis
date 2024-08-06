import pyhidra
import os
import code

#os.environ['GHIDRA_INSTALL_DIR'] = "/app/ghidra_10.3.2_PUBLIC/"

def decompile_func(program):
    with pyhidra.open_program(program) as flat_api:
        print("DECOMPILE FUNC")
        from ghidra.app.decompiler.flatapi import FlatDecompilerAPI
        from ghidra.app.decompiler import DecompInterface
        from ghidra.util.task import ConsoleTaskMonitor
        currentProgram = flat_api.getCurrentProgram()
        func_address = currentProgram.getAddressFactory().getAddress('00101139')
        print("FUNC_ADDRESS")
        print(func_address)
        function = currentProgram.getFunctionManager().getFunctionAt(func_address)
        print("FUNCTION")
        print(function)
        
        decomp_api = FlatDecompilerAPI(flat_api)
        decomp_api.initialize()
        print("DECOMP API")
        print(decomp_api)
        try:
            decomp_result = decomp_api.decompile(function)
        except Exception as e:
            print("ERROR")
            print(e.toString())
        print("RESULTS")
        print(decomp_result)
        decomp_api.dispose()
        
def decompile_func2(program):
    try:
        with pyhidra.open_program(program) as flat_api:
            from ghidra.app.decompiler import DecompInterface
            from ghidra.util.task import ConsoleTaskMonitor
            print("DECOMPILE FUNC")
            currentProgram = flat_api.getCurrentProgram()
            print("CURRENT PROGRAM:", currentProgram)
            
            func_address = currentProgram.getAddressFactory().getAddress('00101139')
            print("FUNC_ADDRESS:", func_address)
            
            function = currentProgram.getFunctionManager().getFunctionAt(func_address)
            print("FUNCTION:", function)
            
            # Using DecompInterface for more control
            decompiler = DecompInterface()
            decompiler.openProgram(currentProgram)
            task_monitor = ConsoleTaskMonitor()
            code.interact(local=dict(globals(), **locals()))
            decomp_result = decompiler.decompileFunction(function, 30, task_monitor)
            
            print("RESULTS:", decomp_result)

            if decomp_result.decompileCompleted():
                print("Decompilation successful!")
                # Process the decompilation result
                decompiled_code = decomp_result.getDecompiledFunction().getC()
                print("Decompiled Code:", decompiled_code)
            else:
                print("Decompilation failed.")
                error_message = decomp_result.getErrorMessage()
                print("Error Message:", error_message)
                lm = decompiler.getLastMessage()
                print("Last message:")
                print(lm)
                # Handle decompilation failure

    except Exception as e:
        print(f"An error occurred: {e}")
        raise e        
decompile_func2("a.out")