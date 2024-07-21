from django.urls import path
from .views import test_view, binary_ingest, probe, cfg, funcs, blocks, disasms

urlpatterns = [
    path('test/', test_view, name='test'),
    path('binary_ingest/', binary_ingest, name='binary_ingest'),
    path('probe/', probe, name='probe'),
    path('cfg/', cfg, name='cfg'),
    
    path('funcs/', funcs, name='funcs'),
    path('blocks/', blocks, name='funcs'),
    path('disasms/', disasms, name='disasms'),
    
    path('proj/', test_view, name='proj'),
    path('func/', test_view, name='func'),
    path('block/', test_view, name='block'),
    path('disasm/', test_view, name='disasm')
]

# funcs/ - return functions by project id
# blocks/ - return blocks by function id
# disasms/ - return disasm by block id

# proj/ - return project info by id
# func/ - return function info by id
# block/ - return block info by id
# disasm/ - return disasm info by id