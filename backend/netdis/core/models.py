from django.db import models

# Create your models here.
class UploadedFile(models.Model):
    file = models.FileField(upload_to="uploads/", max_length=300)
    hash = models.CharField(max_length=256)
    uploaded_at = models.DateTimeField(auto_now_add=True)
    
class Project(models.Model):
    file = models.ForeignKey("UploadedFile", on_delete=models.CASCADE)
    
class Function(models.Model):
    project = models.ForeignKey(Project, on_delete=models.CASCADE)
    name = models.CharField(max_length=256)
    addr = models.CharField(max_length=64)
    def __str__(self):
        return self.name

class Block(models.Model):
    function = models.ForeignKey(Function, on_delete=models.CASCADE)
    addr = models.CharField(max_length=64)

class Disasm(models.Model):
    block = models.ForeignKey(Block, on_delete=models.CASCADE)    
    op = models.CharField(max_length=64)
    data = models.CharField(max_length=64)
    addr = models.CharField(max_length=64)
