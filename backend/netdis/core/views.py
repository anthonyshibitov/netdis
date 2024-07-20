from rest_framework.decorators import api_view, parser_classes, permission_classes
from rest_framework.response import Response
from rest_framework.parsers import MultiPartParser, FormParser
from rest_framework.permissions import IsAuthenticated
from rest_framework import status
from django.http import Http404, HttpResponseBadRequest
from .models import UploadedFile
import hashlib
import angr
import json
import networkx as nx

from functools import wraps
import time

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

@api_view(['GET'])
def test_view(request):
    data = {"result": "test"}
    return Response(data)

@api_view(['POST'])
@parser_classes([MultiPartParser])
def binary_ingest(request):
    if(request.method == 'POST' and request.FILES.get('file')):
        file_obj = request.FILES['file'] 
        contents = file_obj.read()
        
        hash = hashlib.sha256(contents).hexdigest()
        file_obj.name = hash
        
        if UploadedFile.objects.filter(hash = hash).exists():
            print("not making!")
            return Response(hash)
        else:
            print("new file!")
            new_file = UploadedFile(file=file_obj, hash=hash)
            new_file.save()
            return Response(hash)
    return Response("Bad request!", status=status.HTTP_400_BAD_REQUEST)

@api_view(['POST'])
@timer
def cfg(request):
    if(request.body):
        data_dict = json.loads(request.body.decode("utf-8"))
        if UploadedFile.objects.filter(hash = data_dict['hash']).exists():
            file = UploadedFile.objects.filter(hash = data_dict['hash']).first()
            file_path = "./media/" + file.file.name
            proj = angr.Project(file_path, load_options={'auto_load_libs': False})
            cfg = proj.analyses.CFGFast()
            graph = nx.DiGraph()
            dis_list = list()
            for node in cfg.graph.nodes():
                graph.add_node(node)

            for edge in cfg.graph.edges():
                graph.add_edge(edge[0], edge[1])
                
            for node in list(cfg.nodes()):
                try:
                    dis_list.append((hex(node.addr), node.block.disassembly.__str__()))
                except:
                    dis_list.append((hex(node.addr), "NO DISASM"))
            return Response(dis_list)
    return Response("error")

@api_view(['POST'])
def funcs(request):
    if(request.body):
        data_dict = json.loads(request.body.decode("utf-8"))
        if UploadedFile.objects.filter(hash = data_dict['hash']).exists():
            file = UploadedFile.objects.filter(hash = data_dict['hash']).first()
            file_path = "./media/" + file.file.name
            proj = angr.Project(file_path, load_options={'auto_load_libs': False})
            proj.analyses.CFGFast()
            funcs = proj.kb.functions.items()
            funcs_iter = iter(funcs)
            funcs_list = list()
            for func in funcs_iter:
                funcs_list.append((hex(func[0]),func[1].name))
            return Response(funcs_list)
    return Response("BAD")

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def probe(request):
    print(request.user.id)
    return Response(request.user.id)