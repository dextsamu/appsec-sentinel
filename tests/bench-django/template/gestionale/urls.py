from django.urls import path
from soci import views

urlpatterns = [
    path("health/", views.health),
    path("login/", views.login_view),
    path("soci/<int:pk>/", views.socio_detail),
    path("soci/<int:pk>/modifica/", views.socio_update),
    path("ricevute/<int:pk>/", views.ricevuta),
    path("import/", views.import_soci),
    path("anteprima-link/", views.anteprima_link),
    path("cerca/", views.cerca),
]
