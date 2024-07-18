from rest_framework.decorators import api_view, parser_classes
from rest_framework.response import Response
from rest_framework.parsers import MultiPartParser, FormParser
from rest_framework import status
from django.http import Http404, HttpResponseBadRequest
from .models import UploadedFile
import rzpipe
import hashlib

@api_view(['GET'])
def test_view(request):
    data = {"result": "test"}
    return Response(data)

@api_view(['POST'])
@parser_classes([MultiPartParser])
def binary_ingest(request):
    if(request.method == 'POST' and request.FILES.get('file')):
        file_obj = request.FILES['file'] 
        contents = file_obj.read()
        
        hash = hashlib.sha256(contents).hexdigest()
        file_obj.name = hash
        
        if UploadedFile.objects.filter(hash = hash).exists():
            return Response(hash)
        else:
            new_file = UploadedFile(hash=hash)
            new_file.save()
            return Response(hash)
    return Response("Bad request!", status=status.HTTP_400_BAD_REQUEST)

@api_view(['GET'])
def probe(request):
    return Response("probed")