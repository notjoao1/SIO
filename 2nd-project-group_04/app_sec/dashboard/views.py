from django.shortcuts import render, redirect, get_object_or_404
from django.contrib import messages
from django.http import Http404
from django_ratelimit.decorators import ratelimit

from online_shop.decorators import manager_required
from shop.models import Product
from orders.models import Order, OrderItem
from .forms import AddProductForm, AddCategoryForm, EditProductForm
from django.views.decorators.cache import never_cache


def is_manager(user):
    try:
        if not user.is_manager:
            raise Http404
        return True
    except:
        raise Http404


@ratelimit(key='ip', rate='20/m', block=True)
@manager_required
def products(request):
    products = Product.objects.all()
    context = {'title': 'Products', 'products': products}
    return render(request, 'products.html', context)


@ratelimit(key='ip', rate='20/m', block=True)
@manager_required
def add_product(request):
    if request.method == 'POST':
        form = AddProductForm(request.POST, request.FILES)
        if form.is_valid():
            form.save()
            messages.success(request, 'Product added Successfuly!')
            return redirect('dashboard:add_product')
    else:
        form = AddProductForm()
    context = {'title': 'Add Product', 'form': form}
    return render(request, 'add_product.html', context)

@manager_required
def delete_product(request, id):
    product = Product.objects.filter(id=id).delete()
    messages.success(request, 'product has been deleted!', 'success')
    return redirect('dashboard:products')


@ratelimit(key='ip', rate='20/m', block=True)
@manager_required
def edit_product(request, id):
    product = get_object_or_404(Product, id=id)
    if request.method == 'POST':
        form = EditProductForm(request.POST, request.FILES, instance=product)
        if form.is_valid():
            form.save()
            messages.success(request, 'Product has been updated', 'success')
            return redirect('dashboard:products')
    else:
        form = EditProductForm(instance=product)
    context = {'title': 'Edit Product', 'form': form}
    return render(request, 'edit_product.html', context)


@ratelimit(key='ip', rate='20/m', block=True)
@manager_required
def add_category(request):
    if request.method == 'POST':
        form = AddCategoryForm(request.POST)
        if form.is_valid():
            form.save()
            messages.success(request, 'Category added Successfuly!')
            return redirect('dashboard:add_category')
    else:
        form = AddCategoryForm()
    context = {'title': 'Add Category', 'form': form}
    return render(request, 'add_category.html', context)


@ratelimit(key='ip', rate='20/m', block=True)
@manager_required
def orders(request):
    orders = Order.objects.all()
    context = {'title': 'Orders', 'orders': orders}
    return render(request, 'orders.html', context)


@never_cache
@ratelimit(key='ip', rate='30/m', block=True)
@manager_required
def order_detail(request, id):
    order = Order.objects.filter(id=id).first()
    items = OrderItem.objects.filter(order=order).all()
    context = {'title': 'order detail', 'items': items, 'order': order}
    return render(request, 'order_detail.html', context)
