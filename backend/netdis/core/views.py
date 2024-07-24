from rest_framework.decorators import api_view, parser_classes, permission_classes
from rest_framework.response import Response
from rest_framework.parsers import MultiPartParser, FormParser
from rest_framework.permissions import IsAuthenticated
from rest_framework import status
from django.http import Http404, HttpResponseBadRequest
from .models import Task, UploadedFile, Project, Function, Block, Disasm
import hashlib
import json
from .utils import get_project_from_hash, get_functions_from_project, get_blocks_from_function, get_disasm_from_block, analyze_file
from .utils import timer
from django.core.files.storage import FileSystemStorage
from .tasks import analyze_file_task
from .serializers import TaskSerializer

@api_view(['GET'])
def test_view(request):
    data = {"result": "test"}
    return Response(data)

@timer
@api_view(['POST'])
@parser_classes([MultiPartParser])
def binary_ingest(request):
    if(request.method == 'POST' and request.FILES.get('file')):
        file_obj = request.FILES['file'] 
        contents = file_obj.read()
        hash = hashlib.sha256(contents).hexdigest()
        file_obj.name = hash
                
        # Uploaded file, and analysis already exists
        if UploadedFile.objects.filter(hash = hash).exists():
            uploaded_file = UploadedFile.objects.get(hash = hash)
            # Eventually this will return project id based on user, until now, return random project ID
            # They are all the same if they share the same hash
            print("Loading project")
            project = Project.objects.get(file = uploaded_file)
            print("Loaded project")
            print(project)
            return Response({ "project_id": project.id })
        # Uploaded file does not exist. Upload, analyze, and delete it.
        else:
            uploaded_file = UploadedFile(file=file_obj, hash=hash)
            uploaded_file.save()
            
            print("Queueing worker...")
            task = Task(status = "QUEUED", file=uploaded_file, project=None)
            task.save()
            print(f"Task id {task.id}")
            analyze_file_task.delay(uploaded_file.id, task.id)
            serializer = TaskSerializer(task)
            return Response(serializer.data)
 
    return Response("Bad request!", status=status.HTTP_400_BAD_REQUEST)

@api_view(['POST'])
def funcs(request):
    if(request.body):
        data_dict = json.loads(request.body.decode("utf-8"))
        print(data_dict)
        try:
            project_id = data_dict['project_id']
        except Exception as error:
            return Response(f"ERROR: {error.__str__()}")
        return Response(get_functions_from_project(project_id))
    return Response('Bad request!', status=status.HTTP_400_BAD_REQUEST)

@api_view(['POST'])
def blocks(request):
    if(request.body):
        try:
            data_dict = json.loads(request.body.decode("utf-8"))
        except Exception as error:
            return Response(error)
        function_id = data_dict['function_id']
        return Response(get_blocks_from_function(function_id))
    return Response('Bad request!', status=status.HTTP_400_BAD_REQUEST)

@api_view(['POST'])
def disasms(request):
    if(request.body):
        data_dict = json.loads(request.body.decode("utf-8"))
        block_id = data_dict['block_id']
        return Response(get_disasm_from_block(block_id))
    return Response('Bad request!', status=status.HTTP_400_BAD_REQUEST)

@api_view(['GET'])
def task(request, id):
    task = Task.objects.get(pk=id)
    print("task.id")
    print(task.id)
    print("task_id passed")
    print(id)
    serializer = TaskSerializer(task)
    if(task.status == "DONE"):
        task.delete()
        #task.save()
    return Response(serializer.data)

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def probe(request):
    print(request.user.id)
    return Response(request.user.id)

def test_cfg_func(request):
    pass
    # cfg = proj.analyses.CFGFast()
    
    # graph = nx.DiGraph()
    # dis_list = list()
    # for node in cfg.graph.nodes():
    #     graph.add_node(node)

    # for edge in cfg.graph.edges():
    #     graph.add_edge(edge[0], edge[1])