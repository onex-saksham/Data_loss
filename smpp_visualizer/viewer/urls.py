from django.contrib import admin
from django.urls import path
from viewer import views

urlpatterns = [
    path('admin/', admin.site.urls),
    path('', views.search_page, name='search_page'),
    path('generate/', views.generate_csv, name='generate_csv'),
]
