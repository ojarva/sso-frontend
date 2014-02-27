from django.http import Http404
from django.core.exceptions import PermissionDenied, SuspiciousOperation

def raise_404(request, *args, **kwargs):
    raise Http404

def raise_500(request, *args, **kwargs):
    raise Exception

def raise_400(request, *args, **kwargs):
    raise SuspiciousOperation

def raise_403(request, *args, **kwargs):
    raise PermissionDenied
