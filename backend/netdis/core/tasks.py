# Celery tasks
from .models import Task, UploadedFile, Project, Function, Block, Disasm, FileUploadResult, CFGAnalysisResult, DecompAnalysisResult, ErrorResult, RawHexResult, StringsResult, LoadersResult
from celery import shared_task
from .utils import timer
import subprocess
import os
from .ghidra.analysis import ghidra_function_cfg, ghidra_full_disassembly, ghidra_decompile_func, ghidra_get_rawhex, ghidra_get_strings, ghidra_get_loaders
from django.contrib.contenttypes.models import ContentType
import logging

logger = logging.getLogger(__name__)

def get_loaders_task(file_id, task_id):
    file = UploadedFile.objects.get(pk=file_id)
    print(f"Getting task... ID {task_id}")
    task = Task.objects.get(pk=task_id)
    task.status = "ACTIVE"
    task.save()
    file_path = "./media/" + file.file.name
    ghidra_get_loaders.apply_async(args=(file_path,), link=get_loaders_task_callback.s(task.id, file_id))
    
@shared_task()   
def get_loaders_task_callback(loader_result, task_id, file_id):
    file = UploadedFile.objects.get(pk=file_id)
    file.delete()
    task = Task.objects.get(pk=task_id)
    if 'error' in loader_result:
        task.task_type = "error"
        result = ErrorResult.objects.create(error_message=loader_result)
    else:
        task.task_type = "loaders"
        result = LoadersResult.objects.create(loaders=loader_result)
    task.status = "DONE"
    task.content_type = ContentType.objects.get_for_model(result)
    task.object_id = result.id
    task.result = result
    task.save()

def primary_analysis(file_id, task_id, loader, lang):
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
    
    print("Project doesn't exist. Let's make one and analyze the file. Added debug below")
    logger.debug("Project doesn't exist. Let's make one and analyze the file.")
    print(file.file.name)
    file_path = "./media/" + file.file.name
        
    # proj_obj = Project(file = file)
    # proj_obj.save()
    # print(f"Project ID created: {proj_obj.id}")
    # print(f"Project obj id {proj_obj.id}")
    ghidra_full_disassembly.apply_async(args=(task_id, file_path, file_id, loader, lang), link=primary_analysis_callback.s(task.id, file_id))
    
@shared_task()
def primary_analysis_callback(error, task_id, file_id):
    print(f"Finished task id {task_id}")
    # project = Project.objects.get(pk=project_id)
    file = UploadedFile.objects.get(pk=file_id)
    if error and 'error' in error:
        # Do some house cleaning..
        result = ErrorResult.objects.create(error_message=error)
        # project.delete()
        # file = UploadedFile.objects.get(pk=file_id)
        print(f"error {error}")
        file.delete()
    else:
        result = FileUploadResult.objects.create(file=file)
    result.save()
    task = Task.objects.get(pk=task_id)
    if error and 'error' in error:
        task.task_type = "error"
    task.status = "DONE"
    task.content_type = ContentType.objects.get_for_model(result)
    task.object_id = result.id
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
    print("Looking for file id", file_id)
    file = UploadedFile.objects.get(pk=file_id)
    file_path = "./media/" + file.file.name
    ghidra_get_rawhex.apply_async(args=(file_path, address, int(length)), link=get_rawhex_callback.s(task.id))

@shared_task()
def get_rawhex_callback(rawhex_result, task_id):
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
    
def get_strings(file_id, task_id):
    task = Task.objects.get(pk=task_id)
    task.status = "ACTIVE"
    task.save()
    file = UploadedFile.objects.get(pk=file_id)
    file_path = "./media/" + file.file.name
    ghidra_get_strings.apply_async(args=(file_path,), link=get_strings_callback.s(task.id))
    
@shared_task()
def get_strings_callback(strings_result, task_id):
    if 'error' in strings_result:
        result = ErrorResult.objects.create(error_message = strings_result)
    else:
        result = StringsResult.objects.create(strings = strings_result)
    result.save()
    task = Task.objects.get(id=task_id)
    if 'error' in strings_result:
        task.task_type = "error"
    task.status = "DONE"
    task.content_type = ContentType.objects.get_for_model(result)
    task.object_id = result.id
    task.result = result
    task.save()
    
from netdis.core.models import ErrorResult
# from celery.utils.log import get_task_logger

# logger = get_task_logger(__name__)

@shared_task
def test():
    err = ErrorResult.objects.create(error_message="CRONN")
    err.save()
    logger.info("TEST CRON")

