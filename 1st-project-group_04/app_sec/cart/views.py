from django.shortcuts import render, get_object_or_404, redirect
from django.contrib import messages
from django.contrib.auth.decorators import login_required

from cart.utils.cart import Cart
from .forms import QuantityForm
from shop.models import Product
from orders.models import Order

@login_required
def add_to_cart(request, product_id):
    cart = Cart(request)
    product = get_object_or_404(Product, id=product_id)
    quantity = product.quantity
    form = QuantityForm(request.POST, quantity)
    if form.is_valid() and form.cleaned_data['quantity'] + cart.show_quantity(product_id) <= quantity: #fsadfasdf
        data = form.cleaned_data
        cart.add(product=product, quantity=data['quantity'])
        messages.success(request, 'Added to your cart!', 'info')
    else:
        messages.error(request, 'No stock!  ' + str(quantity - cart.show_quantity(product_id)) + " left!", 'danger')
    return redirect('shop:product_detail', slug=product.slug)


@login_required
def add_order_to_cart(request, order_id):
    cart = Cart(request)
    for orderitem in Order.objects.get(id=order_id).items.all():
        cart.add(product=orderitem.product, quantity=orderitem.quantity)
    messages.success(request, 'Added to your cart!', 'info')
    return redirect('cart:show_cart')


@login_required
def show_cart(request):
    cart = Cart(request)
    context = {'title': 'Cart', 'cart': cart}
    return render(request, 'cart.html', context)


@login_required
def remove_from_cart(request, product_id):
    cart = Cart(request)
    product = get_object_or_404(Product, id=product_id)
    cart.remove(product)
    return redirect('cart:show_cart')



@login_required
def update_cart(request):
    cart = Cart(request)
    for key, value in request.POST.items():
        if key.startswith('quantity_'):
            product_id = key.replace('quantity_', '')
            quantity = int(value)
            cart.update(product_id, quantity)


    return redirect('cart:show_cart')
