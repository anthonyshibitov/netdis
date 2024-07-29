import json
from ghidra.app.script import GhidraScript

class ExtractFunctions(GhidraScript):
    def run(self):
        functions = []
        for func in currentProgram.getFunctionManager().getFunctions(True):
            func_info = {
                "name": func.getName(),
                "address": str(func.getEntryPoint())
            }
            print(func.getName())
            functions.append(func_info)
            line = currentProgram.getListing().getInstructions(func.getBody(), True)
            for l in line:
                print(l.getMnemonicString())
                for i in range(l.getNumOperands()):
                    print(l.getDefaultOperandRepresentation(i))
            
        
if __name__ == "__main__":
    extract = ExtractFunctions()
    extract.run()
    
# for func in currentProgram.getFunctionManager().getFunctions(True):
# disassembly = []
# # Get the address set of the function
# function_body = func.getBody()

# # Iterate over instructions in the function body
# instructions = currentProgram.getListing().getInstructions(function_body, True)
# for instruction in instructions:
#     address = instruction.getAddress().toString()
#     mnemonic = instruction.getMnemonicString()
#     operands = instruction.getDefaultOperandRepresentationList()
#     disassembly.append({
#         "address": address,
#         "mnemonic": mnemonic,
#         "operands": operands
#     })

# functions_disassembly.append({
#     "name": func.getName(),
#     "entry_point": func.getEntryPoint().toString(),
#     "disassembly": disassembly
# })