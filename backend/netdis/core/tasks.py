# Celery tasks
from .models import Task, UploadedFile, Project, Function, Block, Disasm, FileUploadResult, CFGAnalysisResult, DecompAnalysisResult, ErrorResult, RawHexResult
from celery import shared_task
from .utils import timer
import subprocess
import os
from .ghidra.analysis import ghidra_function_cfg, ghidra_full_disassembly, ghidra_decompile_func, ghidra_get_rawhex
from django.contrib.contenttypes.models import ContentType

def primary_analysis(file_id, task_id):
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
        
    proj_obj = Project(file = file)
    proj_obj.save()
    print(f"Project ID created: {proj_obj.id}")
    ghidra_full_disassembly.apply_async(args=(file_path, proj_obj.id), link=primary_analysis_callback.s(task.id, proj_obj.id, file_id))
    
@shared_task()
def primary_analysis_callback(error, task_id, project_id, file_id):
    print(f"Finished task id {task_id}")
    print(f"Finished project id {project_id}")
    project = Project.objects.get(pk=project_id)
    if error and 'error' in error:
        # Do some house cleaning..
        result = ErrorResult.objects.create(error_message=error)
        project.delete()
        file = UploadedFile.objects.get(pk=file_id)
        file.delete()
    else:
        result = FileUploadResult.objects.create(project=project)
    result.save()
    task = Task.objects.get(pk=task_id)
    if error and 'error' in error:
        task.task_type = "error"
    task.status = "DONE"
    task.content_type = ContentType.objects.get_for_model(result)
    task.object_id = result.id
    # task.object_id = project_id
    task.result = result
    task.save()
    

def cfg_analysis(file_id, func_id, task_id):
    task = Task.objects.get(pk=task_id)
    task.status = "ACTIVE"
    task.save()
    file = UploadedFile.objects.get(pk=file_id)
    file_path = "./media/" + file.file.name
    ghidra_function_cfg.apply_async(args=(file_path, func_id), link=cfg_analysis_callback.s(task.id))

    
@shared_task()
def cfg_analysis_callback(cfg_result, task_id):
    if 'error' in cfg_result:
        result = ErrorResult.objects.create(error_message=cfg_result)
    else:
        result = CFGAnalysisResult.objects.create(json_result=cfg_result)
    result.save()
    task = Task.objects.get(id=task_id)
    if 'error' in cfg_result:
        task.task_type = "error"
    task.status = "DONE"
    task.content_type = ContentType.objects.get_for_model(result)
    task.object_id = result.id
    task.result = result
    task.save()
        
def get_rawhex(file_id, task_id, address, length):
    task = Task.objects.get(pk=task_id)
    task.status = "ACTIVE"
    task.save()
    file = UploadedFile.objects.get(pk=file_id)
    file_path = "./media/" + file.file.name
    ghidra_get_rawhex.apply_async(args=(file_path, address, length), link=get_rawhex_callback.s(task.id))

@shared_task()
def get_rawhex_callback(rawhex_result, task_id):
    print("RAW HEX CALLBACK CALLED")
    print(rawhex_result)
    if 'error' in rawhex_result:
        result = ErrorResult.objects.create(error_message = rawhex_result)
    else:
        result = RawHexResult.objects.create(raw_hex = rawhex_result)
    result.save()
    task = Task.objects.get(id=task_id)
    if 'error' in rawhex_result:
        task.task_type = "error"
    task.status = "DONE"
    task.content_type = ContentType.objects.get_for_model(result)
    task.object_id = result.id
    task.result = result
    print("RESULT")
    print(result)
    task.save()

    
def decompile_function(file_id, func_id, task_id):
    task = Task.objects.get(pk=task_id)
    task.status = "ACTIVE"
    task.save()
    file = UploadedFile.objects.get(pk=file_id)
    file_path = "./media/" + file.file.name
    ghidra_decompile_func.apply_async(args=(file_path, func_id), link=decompile_function_callback.s(task.id))
    
@shared_task()
def decompile_function_callback(cfg_result, task_id):
    if 'error' in cfg_result:
        result = ErrorResult.objects.create(error_message = cfg_result)
    else:
        result = DecompAnalysisResult.objects.create(decomp_result = cfg_result)
    result.save()
    task = Task.objects.get(id=task_id)
    if 'error' in cfg_result:
        task.task_type = "error"
    task.status = "DONE"
    task.content_type = ContentType.objects.get_for_model(result)
    task.object_id = result.id
    task.result = result
    task.save()
    
from netdis.core.models import ErrorResult
from celery.utils.log import get_task_logger

logger = get_task_logger(__name__)

@shared_task
def test():
    err = ErrorResult.objects.create(error_message="CRONN")
    err.save()
    logger.info("TEST CRON")

