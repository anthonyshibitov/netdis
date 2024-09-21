from rest_framework.decorators import api_view, parser_classes, permission_classes
from rest_framework.response import Response
from rest_framework.parsers import MultiPartParser, FormParser
# from rest_framework.permissions import IsAuthenticated
from rest_framework import status
from django.http import Http404, HttpResponseBadRequest
from .models import Task, UploadedFile, Project, Function, Block, Disasm, FileUploadResult, CFGAnalysisResult, DecompAnalysisResult, ErrorResult, RawHexResult, StringsResult, LoadersResult
import hashlib
import json
from .utils import get_functions_from_file, get_blocks_from_function, get_disasm_from_block, query_storage
from .utils import timer
from .tasks import primary_analysis, cfg_analysis, decompile_function, get_rawhex, get_strings, get_loaders_task
from .serializers import TaskSerializer
import datetime
import os

@api_view(['GET'])
def test_view(request):
    data = {"result": "test"}
    return Response(data)

@api_view(['POST'])
@parser_classes([MultiPartParser])
def get_loaders(request):
    if(request.method == 'POST' and request.FILES.get('file')):
        file_obj = request.FILES['file'] 
        file_size = file_obj.size
        contents = file_obj.read()
        hash = hashlib.sha256(contents).hexdigest()
        file_obj.name = hash
        max_file_size = int(os.environ.get("MAX_FILE_SIZE"))
        if(file_size > max_file_size):
            # Reject if file is over 5mb
            return Response({"error": "File too large", "error_info": file_size}, status=status.HTTP_400_BAD_REQUEST)
        
                
        # if UploadedFile.objects.filter(hash = hash).exists():
        #     # Uploaded file, and analysis already exists
        #     uploaded_file = UploadedFile.objects.get(hash = hash)
        #     project = Project.objects.get(file = uploaded_file)
        #     print("Loaded project")
        #     print(project)
        #     return Response({ "project_id": project.id, "file_id": uploaded_file.id })
        # else:
        #     # Uploaded file does not exist. Upload, analyze, and delete it.
        query_storage()
        uploaded_file = UploadedFile(file=file_obj, hash=hash, file_size=file_size)
        uploaded_file.save()
        uploaded_file.evict_at = uploaded_file.uploaded_at + datetime.timedelta(days=2)
        uploaded_file.save()
        
        print("Queueing worker...")
        task = Task(status = "QUEUED", task_type='get_loaders')
        task.save()
        print(f"Task id {task.id}")
        get_loaders_task(uploaded_file.id, task.id)
        serializer = TaskSerializer(task)
        return Response(serializer.data)
 
    return Response("Bad request!", status=status.HTTP_400_BAD_REQUEST)

@timer
@api_view(['POST'])
@parser_classes([MultiPartParser])
def binary_ingest(request):
    if(request.method == 'POST' and request.FILES.get('file')):
        if request.data.get('loader'):
            loader = request.data.get('loader')
        else:
            loader = None
        if request.data.get('lang'):
            lang = request.data.get('lang')
        else:
            lang = None
        file_obj = request.FILES['file'] 
        file_size = file_obj.size
        contents = file_obj.read()
        hash = hashlib.sha256(contents).hexdigest()
        file_obj.name = hash
        max_file_size = int(os.environ.get("MAX_FILE_SIZE"))
        if(file_size > max_file_size):
            # Reject if file is over 5mb
            return Response({"error": "File too large", "error_info": file_size}, status=status.HTTP_400_BAD_REQUEST)
                
        if UploadedFile.objects.filter(hash = hash).exists():
            # Uploaded file, and analysis already exists
            uploaded_file = UploadedFile.objects.get(hash = hash)
            # project = Project.objects.get(file = uploaded_file)
            print("Loaded file")
            print(uploaded_file)
            return Response({ "file_id": uploaded_file.id })
        else:
            # Uploaded file does not exist. Upload, analyze, and delete it.
            query_storage()
            uploaded_file = UploadedFile(file=file_obj, hash=hash, file_size=file_size)
            uploaded_file.save()
            uploaded_file.evict_at = uploaded_file.uploaded_at + datetime.timedelta(days=2)
            uploaded_file.save()
            
            print("Queueing worker...")
            task = Task(status = "QUEUED", task_type='file_upload')
            task.save()
            print(f"File id {uploaded_file.id}")
            print(f"Task id {task.id}")
            print(f"USING LOADER: {loader}")
            print(f"USING LANG: {lang}")
            primary_analysis(uploaded_file.id, task.id, loader, lang)
            serializer = TaskSerializer(task)
            return Response(serializer.data)
 
    return Response("Bad request!", status=status.HTTP_400_BAD_REQUEST)

@api_view(['POST'])
def funcs(request):
    if(request.body):
        data_dict = json.loads(request.body.decode("utf-8"))
        try:
            file_id = data_dict['file_id']
        except Exception as error:
            return Response(f"ERROR: {error.__str__()}")
        print("Loading funcs for file_id", file_id)
        print(get_functions_from_file(file_id))
        return Response(get_functions_from_file(file_id))
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
        try:
            data_dict = json.loads(request.body.decode("utf-8"))
        except Exception as error:
            return Response(error)
        block_id = data_dict['block_id']
        return Response(get_disasm_from_block(block_id))
    return Response('Bad request!', status=status.HTTP_400_BAD_REQUEST)

@api_view(['POST'])
def raw(request):
    if(request.body):
        try:
            data_dict = json.loads(request.body.decode("utf-8"))
        except Exception as error:
            return Response(error)
        address = data_dict['address']
        print(f"Looking for address {address}")
        return(status.HTTP_200_OK)
    return Response('Bad request!', status=status.HTTP_400_BAD_REQUEST)

@api_view(['GET'])
def task(request, id):
    try:
        task = Task.objects.get(pk=id)
        serializer = TaskSerializer(task)
        response = serializer.data
        if task.status == "DONE":
            print(f"task type: {task.task_type}")
            match task.task_type:
                case 'file_upload':
                    print("trying..")
                    upload_result = FileUploadResult.objects.get(id=task.object_id)
                    result = upload_result
                    print(f"POLLING TASK is asking for file id {result.file_id}")
                    response["result"] = {"file_id": result.file_id}
                case 'cfg_analysis':
                    result = CFGAnalysisResult.objects.get(id=task.object_id)
                    response["result"] = {"json_result": result.json_result}
                case 'decomp_func':
                    result = DecompAnalysisResult.objects.get(id=task.object_id)
                    response['result'] = {"decomp_result": result.decomp_result}
                case 'raw_request':
                    result = RawHexResult.objects.get(id=task.object_id)
                    response['result'] = {"rawhex": result.raw_hex}
                case 'strings':
                    result = StringsResult.objects.get(id=task.object_id)
                    response['result'] = {"strings": result.strings}
                case 'error':
                    result = ErrorResult.objects.get(id=task.object_id)
                    response['result'] = {"error": result.error_message}
                case 'loaders':
                    print("GIVE BACK LOADERS")
                    result = LoadersResult.objects.get(id=task.object_id)
                    response['result'] = {"loaders": result.loaders}
            task.delete()
        return Response(response)
    except Exception as e:
        return Response('Task does not exist', status=status.HTTP_400_BAD_REQUEST)

@api_view(['POST'])
def func_graph(request):
    if(request.body):
        data_dict = json.loads(request.body.decode("utf-8"))
        func_id = data_dict['function_id']
        file_id = data_dict['file_id']
        task = Task.objects.create(task_type='cfg_analysis')
        task.save()
        cfg_analysis(file_id, func_id, task.id)
        return Response({"task_id": task.id, "status": task.status})
    return Response('Bad request!', status=status.HTTP_400_BAD_REQUEST)
    
@api_view(['POST'])
def decomp_func(request):
    if(request.body):
        data_dict = json.loads(request.body.decode("utf-8"))
        func_id = data_dict['function_id']
        file_id = data_dict['file_id']
        task = Task.objects.create(task_type='decomp_func')
        task.save()
        decompile_function(file_id, func_id, task.id)
        return Response({"task_id": task.id, "status": task.status})
    return Response('Bad request!', status=status.HTTP_400_BAD_REQUEST)

@api_view(['POST'])
def rawhex(request):
    if(request.body):
        data_dict = json.loads(request.body.decode("utf-8"))
        file_id = data_dict['file_id']
        address = data_dict['address']
        length = data_dict['length']
        task = Task.objects.create(task_type='raw_request')
        task.save()
        print(f"Address: {address}, length: {length}, file id {file_id}")
        get_rawhex(file_id, task.id, address, length)
        return Response({"task_id": task.id, "status": task.status})
    return Response('Bad request!', status=status.HTTP_400_BAD_REQUEST)

@api_view(['POST'])
def strings(request):
    if(request.body):
        print("GOOD REQUEST")
        data_dict = json.loads(request.body.decode("utf-8"))
        file_id = data_dict['file_id']
        task = Task.objects.create(task_type='strings')
        task.save()
        get_strings(file_id, task.id)
        return Response({"task_id": task.id, "status": task.status})
    return Response('Bad request!', status=status.HTTP_400_BAD_REQUEST)