# Celery tasks
from .models import Task, UploadedFile, Project, Function, Block, Disasm
from celery import shared_task
from .utils import timer
import subprocess
import os
from .ghidra.tests import full_disasm, func_cfg

@shared_task()
@timer
def print_test(file_id, task_id):
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
    
    full_disasm(file_path, proj_obj)
    
    print("Worker analysis done!")
    task.status = "DONE"
    task.project = proj_obj
    task.save()
    #file.delete()

@shared_task()
@timer
def func(file_id, func_id):
    file = UploadedFile.objects.get(pk=file_id)
    file_path = "./media/" + file.file.name
    func_cfg(file_path, func_id)