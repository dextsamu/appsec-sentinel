from django.contrib.auth.models import User
from django.db import models


class Sezione(models.Model):
    nome = models.CharField(max_length=100)


class Socio(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    sezione = models.ForeignKey(Sezione, on_delete=models.CASCADE)
    telefono = models.CharField(max_length=30, blank=True)
    ruolo = models.CharField(max_length=20, default="VOLONTARIO")


class Ricevuta(models.Model):
    socio = models.ForeignKey(Socio, on_delete=models.CASCADE)
    importo = models.DecimalField(max_digits=8, decimal_places=2)
    codice_fiscale = models.CharField(max_length=16)
