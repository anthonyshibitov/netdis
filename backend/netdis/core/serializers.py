from rest_framework import serializers
from .models import Function

class FunctionSerializer(serializers.Serializer):
    id = serializers.IntegerField()
    project_id = serializers.IntegerField()
    addr = serializers.CharField(max_length=64)
    name = serializers.CharField(max_length=256)

class BlockSerializer(serializers.Serializer):
    id = serializers.IntegerField()
    function_id = serializers.IntegerField()
    addr = serializers.CharField(max_length=64)
    
class DisasmSerializer(serializers.Serializer):
    id = serializers.IntegerField()
    block_id = serializers.IntegerField()
    addr = serializers.CharField(max_length=64)
    op = serializers.CharField(max_length=64)
    data = serializers.CharField(max_length=64)
    
class TaskSerializer(serializers.Serializer):
    id = serializers.IntegerField()
    status = serializers.CharField(max_length=16)
    project_id = serializers.IntegerField()