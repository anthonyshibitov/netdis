from django.urls import path
from .views import *

urlpatterns = [
    path('test/', test_view, name='test'),
    path('binary_ingest/', binary_ingest, name='binary_ingest'),
    path('probe/', probe, name='probe'),
    
    path('funcs/', funcs, name='funcs'),
    path('blocks/', blocks, name='funcs'),
    path('disasms/', disasms, name='disasms'),
    
    path('task/<int:id>', task, name='task'),
    
    path('func_graph/', func_graph, name='func_graph'),
    
    path('proj/', test_view, name='proj'),
    path('func/', test_view, name='func'),
    path('block/', test_view, name='block'),
    path('disasm/', test_view, name='disasm'),
]
