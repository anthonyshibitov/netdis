from rest_framework.decorators import api_view, parser_classes
from rest_framework.response import Response
from rest_framework.parsers import MultiPartParser, FormParser
from django.http import Http404
import rzpipe

@api_view(['GET'])
def test_view(request):
    data = {"result": "test"}
    return Response(data)

@api_view(['POST'])
@parser_classes([MultiPartParser])
def binary_ingest(request):
    if(request.method == 'POST' and request.FILES.get('file')):
        data = request.data
        file_obj = request.FILES['file']
        contents = file_obj.read()
        data = {"result": "thankyouu"}
        with open("test", "wb") as bin:
            bin.write(contents)
        
        pipe = rzpipe.open("test")
        pipe.cmd("aaa")
        pipe.cmd("s entry0")
        res = pipe.cmd("pi 100")
        print(res)
        
        return Response(res)
    raise Http404