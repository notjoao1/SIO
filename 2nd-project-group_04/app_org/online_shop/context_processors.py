from cart.utils.cart import Cart
from shop.models import Category


def return_cart(request):
    cart = len(list(Cart(request)))
    return {'cart_count': cart}


def return_categories(request):
    all_categories = []
    for c in Category.objects.all():
        if not c.has_parent():
            all_categories += c.get_all_categories()
    return {'categories': all_categories }