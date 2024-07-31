from rest_framework import serializers
from .models import Function, UploadedFile, Project, Task, Block, Disasm

class FunctionSerializer(serializers.ModelSerializer):
    class Meta:
        model = Function
        fields = '__all__'

class BlockSerializer(serializers.ModelSerializer):
    class Meta:
        model = Block
        fields = '__all__'

class DisasmSerializer(serializers.ModelSerializer):
    class Meta:
        model = Disasm
        fields = '__all__'

class TaskSerializer(serializers.ModelSerializer):
    file = serializers.PrimaryKeyRelatedField(queryset=UploadedFile.objects.all())
    project = serializers.PrimaryKeyRelatedField(queryset=Project.objects.all(), required=False, allow_null=True)
    
    class Meta:
        model = Task
        fields = '__all__'
