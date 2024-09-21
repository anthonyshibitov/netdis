from .models import UploadedFile, Project, Function, Block, Disasm
from functools import wraps
from .serializers import FunctionSerializer, BlockSerializer, DisasmSerializer
import time
import os
import shutil

def query_storage():
    """
    Check if total storage has been exceeded. If so, delete files until we are below the limit.
    """
    max_size = int(os.environ["MAX_STORAGE"])
    files = UploadedFile.objects.all().order_by('uploaded_at')
    total_size = sum(file.file.size for file in files)
    while total_size > max_size:
        oldest = files.first()
        if os.path.exists(oldest.file.path):
            os.remove(oldest.file.path)
            shutil.rmtree(oldest.file.path + "_ghidra")
        total_size -= oldest.size
        oldest.delete()

def get_project_from_hash(hash):
    if UploadedFile.objects.filter(hash = hash).exists():
        uploadedfile = UploadedFile.objects.get(hash = hash)
        try:
            project_id = Project.objects.get(file=uploadedfile)
            return project_id
        except:
            return None
    return None

def get_functions_from_file(file_id):
    function_list = Function.objects.filter(file_id=int(file_id))
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