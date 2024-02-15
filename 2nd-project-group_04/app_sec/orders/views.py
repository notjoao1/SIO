from django.shortcuts import render, redirect, get_object_or_404
from django.contrib import messages
from django.http import FileResponse
from django.conf import settings
from online_shop.decorators import verified_required
from .models import Order, OrderItem
from shop.models import Product
from cart.utils.cart import Cart

import os

from .utils import create_invoice, invoice_belongs_to_user
from django.views.decorators.cache import never_cache
from django_ratelimit.decorators import ratelimit


@ratelimit(key='ip', rate='15/m', block=True)
@verified_required
def create_order(request):
    if request.session.get("valid_otp_sensitive") != True:
        request.session["redirect_to"] = "orders:create_order"
        return redirect('accounts:reauth_2s')

    cart = Cart(request)
    order = Order.objects.create(user=request.user)
    for item in cart:
        product = Product.objects.get(id = item['product']['id'])
        OrderItem.objects.create(
            order=order, product=product,
            price=item['price'], quantity=item['quantity']
        )
        product.quantity -= item['quantity']
        product.save()
    ## CREATE INVOICE FOR ORDER
    create_invoice(order.id)
    del request.session["valid_otp_sensitive"]
    del request.session["cart"]
    return redirect('orders:pay_order', order_id=order.id)


@never_cache
@ratelimit(key='ip', rate='10/m', block=True)
@verified_required
def checkout(request, order_id):
    order = get_object_or_404(Order, id=order_id)
    context = {'title': 'Checkout', 'order': order}
    return render(request, 'checkout.html', context)


@verified_required
def fake_payment(request, order_id):
    cart = Cart(request)
    cart.clear()
    order = get_object_or_404(Order, id=order_id)
    order.status = True
    order.save()
    return redirect('orders:user_orders')


@never_cache
@ratelimit(key='ip', rate='30/m', block=True)
@verified_required
def user_orders(request):
    orders = request.user.orders.all()
    context = {'title': 'Orders', 'orders': orders}
    return render(request, 'user_orders.html', context)


@ratelimit(key='ip', rate='10/m', block=True)
@verified_required
def reorder(request):
    return redirect('cart:show_cart')


@never_cache
@ratelimit(key='ip', rate='15/m', block=True)
@verified_required
def download_invoice(request):
    file_name = request.GET.get("file")

    invoices_path = os.path.join(settings.MEDIA_ROOT, "invoices")
    path = os.path.join(invoices_path, file_name)
    # absolute path, consumes all '../', needed to check for common path 
    abs_path = os.path.abspath(path)

    order_id = file_name.split(".")[0]
    # allow download if user who requested download made the order aswell
    # prevent path traversal by checking that requested file in inside the invoices_path directory
    if invoice_belongs_to_user(request.user.id, order_id) and (
            os.path.commonpath([abs_path, invoices_path]) == invoices_path):
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

    messages.error(request, 'You are not allowed to download that file.', 'danger')
    return redirect('shop:home_page')
