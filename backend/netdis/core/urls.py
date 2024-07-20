from django.urls import path
from .views import test_view, binary_ingest, probe, cfg, funcs

urlpatterns = [
    path('test/', test_view, name='test'),
    path('binary_ingest/', binary_ingest, name='binary_ingest'),
    path('probe/', probe, name='probe'),
    path('cfg/', cfg, name='cfg'),
    path('funcs/', funcs, name='funcs')
]