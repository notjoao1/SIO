from django.urls import path

from cart import views

app_name = 'cart'

urlpatterns = [
    path('add/<product_id>/', views.add_to_cart, name='add_to_cart'),
    path('addorder/<order_id>', views.add_order_to_cart, name='add_order_to_cart'),
    path('remove/<product_id>/', views.remove_from_cart, name='remove_from_cart'),
    path('list/', views.show_cart, name='show_cart'),
    path('update_cart/', views.update_cart, name='update_cart'),
]