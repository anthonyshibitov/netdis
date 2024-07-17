from django.urls import path
from .views import test_view, binary_ingest

urlpatterns = [
    path('test/', test_view, name='test'),
    path('binaryIngest/', binary_ingest, name='test')
]