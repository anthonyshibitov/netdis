# Celery tasks
from .models import Task, UploadedFile, Project, Function, Block, Disasm
import angr
from celery import shared_task
import networkx as nx
from .utils import timer

@shared_task()
@timer
def analyze_file_task(file_id, task_id):
    file = UploadedFile.objects.get(pk=file_id)
    print(f"Getting task... ID {task_id}")
    task = Task.objects.get(pk=task_id)
    task.status = "ACTIVE"
    task.save()
    # Check if Project object already exists with this hash
    if(Project.objects.filter(file=file)).exists():
        proj_obj = Project.objects.get(file=file)
        print("Project already exists. Returning project ID...")
        return proj_obj.id
    
    print("Project doesn't exist. Let's make one and analyze the file.")
    print(file.file.name)
    file_path = "./media/" + file.file.name
    proj = angr.Project(file_path, load_options={'auto_load_libs': False})
    
    proj_obj = Project(file = file)
    proj_obj.save()
    print(f"Project ID created: {proj_obj.id}")
    # HEAVY PART!
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
                
    print("Worker analysis done!")
    task.status = "DONE"
    task.project = proj_obj
    task.save()
    file.delete()
    
    print("Calling func traversal")
    for func in cfg.kb.functions.values():
        traversal = FunctionTraversal()
        traversal.traverse(cfg.get_node(func.addr))  
        #print(func.name)
        #print(traversal.get_graph()) 
        
    
    
    
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
        if(successors != []):
            for successor in successors:
                self.edges.append((node, successor))
                self.graph.add_edge(node, successor)
                if successor not in self.visited:
                    self.traverse(successor)