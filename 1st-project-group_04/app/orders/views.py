from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required

from django.views.decorators.http import require_POST
from django.utils import timezone
from django.http import HttpResponse, FileResponse
from django.conf import settings
from django.contrib import messages


from .models import Order, OrderItem
from cart.utils.cart import Cart

import os

from .utils import create_invoice

@login_required
def create_order(request):
    cart = Cart(request)
    order = Order.objects.create(user=request.user)
    for item in cart:
        OrderItem.objects.create(
            order=order, product=item['product'],
            price=item['price'], quantity=item['quantity']
        )
        item['product'].quantity -= item['quantity']
        item['product'].save()
    ## CREATE INVOICE FOR ORDER
    create_invoice(order.id)
    return redirect('orders:pay_order', order_id=order.id)


@login_required
def checkout(request, order_id):
    order = get_object_or_404(Order, id=order_id)
    context = {'title':'Checkout' ,'order':order}
    return render(request, 'checkout.html', context)


@login_required
def fake_payment(request, order_id):
    cart = Cart(request)
    cart.clear()
    order = get_object_or_404(Order, id=order_id)
    order.status = True
    order.save()
    return redirect('orders:user_orders')


@login_required
def user_orders(request):
    orders = request.user.orders.all()
    context = {'title':'Orders', 'orders': orders}
    return render(request, 'user_orders.html', context)


@login_required
def reorder(request):
    print(request)
    return redirect('cart:show_cart')

@login_required
def download_invoice(request):
    file_name = request.GET.get("file")
    # Invoices are located at /media/invoices/
    invoices_path = os.path.join(settings.MEDIA_ROOT, "invoices")
    path = os.path.join(invoices_path, file_name)
    
    order_id = file_name.split(".")[0]
    try:
        if not os.path.exists(path):
            create_invoice(order_id)
        # serve file for download here
        response = FileResponse(open(path, 'rb'))
        response['Content-Type'] = 'application/octet-stream'
        response['Content-Disposition'] = f'attachment; filename="{file_name}"'
        return response
    except Exception as e:
        print("Exception ocurred: ", e)


    messages.error(request, 'Invalid invoice file requested.', 'danger')
    return redirect('shop:home_page')