# Celery tasks
from .models import Task, UploadedFile, Project, Function, Block, Disasm, FileUploadResult, CFGAnalysisResult, DecompAnalysisResult
from celery import shared_task
from .utils import timer
import subprocess
import os
from .ghidra.analysis import ghidra_function_cfg, ghidra_full_disassembly, ghidra_decompile_func
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
    ghidra_full_disassembly.apply_async(args=(file_path, proj_obj.id), link=primary_analysis_callback.s(task.id, proj_obj.id))
    print("Worker analysis done!")
    
@shared_task()
def primary_analysis_callback(not_used, task_id, project_id):
    project = Project.objects.get(pk=project_id)
    result = FileUploadResult.objects.create(project=project)
    result.save()
    task = Task.objects.get(pk=task_id)
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
    result = CFGAnalysisResult.objects.create(json_result=cfg_result)
    result.save()
    task = Task.objects.get(id=task_id)
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
def decompile_function_callback(result, task_id):
    result = DecompAnalysisResult.objects.create(decomp_result=result)
    result.save()
    task = Task.objects.get(id=task_id)
    task.status = "DONE"
    task.content_type = ContentType.objects.get_for_model(result)
    task.object_id = result.id
    task.result = result
    task.save()