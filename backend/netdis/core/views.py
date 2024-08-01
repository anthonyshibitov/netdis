from rest_framework.decorators import api_view, parser_classes, permission_classes
from rest_framework.response import Response
from rest_framework.parsers import MultiPartParser, FormParser
from rest_framework.permissions import IsAuthenticated
from rest_framework import status
from django.http import Http404, HttpResponseBadRequest
from .models import Task, UploadedFile, Project, Function, Block, Disasm, FileUploadResult, CFGAnalysisResult
import hashlib
import json
from .utils import get_functions_from_project, get_blocks_from_function, get_disasm_from_block
from .utils import timer
from django.core.files.storage import FileSystemStorage
from .tasks import primary_analysis, cfg_analysis
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
            project = Project.objects.get(file = uploaded_file)
            print("Loaded project")
            print(project)
            return Response({ "project_id": project.id })
        # Uploaded file does not exist. Upload, analyze, and delete it.
        else:
            uploaded_file = UploadedFile(file=file_obj, hash=hash)
            uploaded_file.save()
            
            print("Queueing worker...")
            task = Task(status = "QUEUED", task_type='file_upload')
            task.save()
            print(f"Task id {task.id}")
            primary_analysis(uploaded_file.id, task.id)
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

@api_view(['POST'])
def block_srcs(request):
    pass

@api_view(['POST'])
def block_dsts(request):
    pass

@api_view(['GET'])
def task(request, id):
    task = Task.objects.get(pk=id)
    
    serializer = TaskSerializer(task)
    response = serializer.data
    
    if task.status == "DONE":
        match task.task_type:
            case 'file_upload':
                result = FileUploadResult.objects.get(id=task.object_id)
                response["result"] = {"project_id": result.project.id}
            case 'cfg_analysis':
                result = CFGAnalysisResult.objects.get(id=task.object_id)
                response["result"] = {"json_result": result.json_result}
    return Response(response)

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def probe(request):
    print(request.user.id)
    return Response(request.user.id)

@api_view(['POST'])
def func_graph(request):
    if(request.body):
        data_dict = json.loads(request.body.decode("utf-8"))
        func_id = data_dict['function_id']
        file_id = data_dict['file_id']
        print("CALLING CFG")
        task = Task.objects.create(task_type='cfg_analysis')
        task.save()
        cfg_analysis(file_id, func_id, task.id)
        return Response({"task_id": task.id, "status": task.status})
    
@api_view(['POST'])
def proj_to_file(request):
    if(request.body):
        pass