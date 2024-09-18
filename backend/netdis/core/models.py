from django.db import models
from django.contrib.contenttypes.fields import GenericForeignKey
from django.contrib.contenttypes.models import ContentType
from netdis import settings
import os

class UploadedFile(models.Model):
    file = models.FileField(upload_to="uploads/", max_length=300)
    hash = models.CharField(max_length=256)
    uploaded_at = models.DateTimeField(auto_now_add=True)
    evict_at = models.DateTimeField(null=True, blank=True)
    file_size = models.IntegerField()

    
class Project(models.Model):
    file = models.ForeignKey(UploadedFile, on_delete=models.CASCADE)
    
class Function(models.Model):
    project = models.ForeignKey(Project, on_delete=models.CASCADE)
    addr = models.CharField(max_length=64)
    name = models.CharField(max_length=256)
    cfg = models.BooleanField(default=False)
    def __str__(self):
        return self.name

class Block(models.Model):
    function = models.ForeignKey(Function, on_delete=models.CASCADE)
    src = models.ManyToManyField('self', related_name="src_blocks", symmetrical=False, blank=True)
    dst = models.ManyToManyField('self', related_name="dst_blocks", symmetrical=False, blank=True)
    addr = models.CharField(max_length=64)

class Disasm(models.Model):
    block = models.ForeignKey(Block, on_delete=models.CASCADE)   
    addr = models.CharField(max_length=64) 
    op = models.CharField(max_length=64)
    data = models.CharField(max_length=64)
    
class Task(models.Model):
    task_type = models.CharField(max_length=64, default="default")
    status = models.CharField(max_length=16)
    
    content_type = models.ForeignKey(ContentType, on_delete=models.CASCADE, null=True, blank=True)
    object_id = models.PositiveIntegerField(null=True, blank=True)
    result = GenericForeignKey('content_type', 'object_id')
    
class FileUploadResult(models.Model):
    file = models.ForeignKey(UploadedFile, on_delete=models.CASCADE, null=True, blank=True)
    
class CFGAnalysisResult(models.Model):
    json_result = models.JSONField()
    
class DecompAnalysisResult(models.Model):
    decomp_result = models.TextField(null=True, blank=True)
    
class ErrorResult(models.Model):
    error_message = models.TextField(null=True, blank=True)
    
class RawHexResult(models.Model):
    raw_hex = models.TextField(null=True, blank=True)
    
class StringsResult(models.Model):
    strings = models.JSONField()
    
class LoadersResult(models.Model):
    loaders = models.JSONField()