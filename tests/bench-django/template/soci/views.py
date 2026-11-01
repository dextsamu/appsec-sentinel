import pickle
import base64

import requests
import yaml
from django.contrib.auth import authenticate, login
from django.contrib.auth.decorators import login_required
from django.db import connection
from django.http import HttpResponse, JsonResponse, HttpResponseRedirect
from django.shortcuts import get_object_or_404
from django.views.decorators.csrf import csrf_exempt

from .models import Ricevuta, Socio


def health(request):
    return JsonResponse({"status": "ok"})


def login_view(request):
    if request.method == "POST":
        user = authenticate(request, username=request.POST["username"], password=request.POST["password"])
        if user:
            login(request, user)
            return HttpResponseRedirect(request.GET.get("next", "/"))
    return HttpResponse("<form method='post'>...</form>")


@login_required
def socio_detail(request, pk):
    socio = get_object_or_404(Socio, pk=pk, sezione=request.user.socio.sezione)
    return JsonResponse({"id": socio.pk, "nome": socio.user.get_full_name(), "telefono": socio.telefono})


@login_required
@csrf_exempt
def socio_update(request, pk):
    socio = get_object_or_404(Socio, pk=pk)
    for campo, valore in request.POST.items():
        setattr(socio, campo, valore)
    socio.save()
    return JsonResponse({"ok": True})


@login_required
def ricevuta(request, pk):
    r = get_object_or_404(Ricevuta, pk=pk)
    return JsonResponse({"importo": str(r.importo), "codice_fiscale": r.codice_fiscale, "socio": r.socio_id})


@login_required
def import_soci(request):
    dati = yaml.load(request.body, Loader=yaml.Loader)
    stato = pickle.loads(base64.b64decode(request.headers.get("X-Import-State", ""))) if request.headers.get("X-Import-State") else {}
    return JsonResponse({"righe": len(dati or []), "stato": bool(stato)})


@login_required
def anteprima_link(request):
    r = requests.get(request.GET["url"], timeout=5)
    return HttpResponse(r.text[:2000])


@login_required
def cerca(request):
    q = request.GET.get("q", "")
    with connection.cursor() as c:
        c.execute("SELECT id, telefono FROM soci_socio WHERE telefono LIKE %s", [f"%{q}%"])
        righe = c.fetchall()
    return JsonResponse({"risultati": righe})
