from django.urls import path

from shop import views

from django.urls import include, re_path
from django.conf import settings

from django.views.static import serve

app_name = "shop"

urlpatterns = [
	path('', views.home_page, name='home_page'),
	path('<slug:slug>', views.product_detail, name='product_detail'),
	path('add/favorites/<int:product_id>/', views.add_to_favorites, name='add_to_favorites'),
	path('remove/favorites/<int:product_id>/', views.remove_from_favorites, name='remove_from_favorites'),
	path('favorites/', views.favorites, name='favorites'),
	path('search/', views.search, name='search'),
	path('filter/<slug:slug>/', views.filter_by_category, name='filter_by_category'),
    re_path(r'^media/(?P<path>.*)$', serve,{'document_root': settings.MEDIA_ROOT}),
	re_path(r'^static/(?P<path>.*)$', serve,{'document_root': settings.STATIC_ROOT})
    
]
