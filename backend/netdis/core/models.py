from django.db import models

# Create your models here.
class UploadedFile(models.Model):
    file = models.FileField(upload_to="uploads/", max_length=300)
    hash = models.CharField(max_length=256)
    uploaded_at = models.DateTimeField(auto_now_add=True)