from .models import UploadedFile, Project, Function, Block, Disasm
from functools import wraps
from .serializers import FunctionSerializer, BlockSerializer, DisasmSerializer
import time
import angr
import networkx as nx

def get_project_from_hash(hash):
    if UploadedFile.objects.filter(hash = hash).exists():
        uploadedfile = UploadedFile.objects.get(hash = hash)
        try:
            project_id = Project.objects.get(file=uploadedfile)
            return project_id
        except:
            return None
    return None

def get_functions_from_project(project_id):
    function_list = Function.objects.filter(project_id=int(project_id))
    serializer = FunctionSerializer(function_list, many=True)
    return serializer.data


def get_blocks_from_function(function_id):
    block_list = Block.objects.filter(function_id=int(function_id))
    serializer = BlockSerializer(block_list, many=True)
    return serializer.data

def get_disasm_from_block(block_id):
    disasm_list = Disasm.objects.filter(block_id=int(block_id))
    serializer = DisasmSerializer(disasm_list, many=True)
    return serializer.data

def analyze_file(file):
    # Check if Project object already exists with this hash
    if(Project.objects.filter(file=file)).exists():
        proj_obj = Project.objects.get(file=file)
        print("Project already exists. Returning ID...")
        return proj_obj.id
    
    # Upload file, analyze, and delete it
    print("Project doesn't exist. Let's make one and analyze the file.")
    print(file.file.name)
    file_path = "./media/" + file.file.name
    proj = angr.Project(file_path, load_options={'auto_load_libs': False})
    
    # Make Project object and assign UploadedFile to it
    proj_obj = Project(file = file)
    proj_obj.save()
    print(f"Project ID loaded: {proj_obj.id}")
    cfg = proj.analyses.CFGFast()
    
    for func in cfg.kb.functions.values():
        function_obj = Function(project = proj_obj, name = func.name, addr = hex(func.addr))
        function_obj.save()
        for block in func.blocks:
            cb = proj.factory.block(block.addr).capstone
            block_obj = Block(function = function_obj, addr = hex(block.addr))
            block_obj.save()
            for insn in cb.insns:
                disasm_obj = Disasm(block = block_obj, op = insn.mnemonic, data = insn.op_str, addr = hex(insn.address))
                disasm_obj.save()    
    
    for func in cfg.kb.functions.values():
        traversal = FunctionTraversal()
        traversal.traverse(func.addr)    
    
class FunctionTraversal:
    def __init__(self):
        self.visited = []
        self.edges = []
        self.graph = nx.DiGraph()
        
    def get_graph(self):
        return self.graph
    
    def traverse(self, node):
        self.graph.add_node(node, label=node.name)
        self.visited.append(node)
        successors = node.successors
        print("\n")
        print("NODE:", node)
        if(successors != []):
            print("SUCCESSORS:", successors)
            for successor in successors:
                self.edges.append((node, successor))
                self.graph.add_edge(node, successor)
                if successor in self.visited:
                    print(node, "LOOPS BACK TO", successor)
                else:
                    self.traverse(successor)
        else:
            print("*** END", node, "NO SUCCESSORS, LEAF NODE!")

def timer(func):
    """helper function to estimate view execution time"""

    @wraps(func)  # used for copying func metadata
    def wrapper(*args, **kwargs):
        # record start time
        start = time.time()

        # func execution
        result = func(*args, **kwargs)
        
        duration = (time.time() - start) * 1000
        # output execution time to console
        print('view {} takes {:.2f} ms'.format(
            func.__name__, 
            duration
            ))
        return result
    return wrapper