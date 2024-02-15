from shop.models import Product
from django.forms.models import model_to_dict

CART_SESSION_ID = 'cart'


class Cart:
    def __init__(self, request):
        self.session = request.session
        self.cart = self.add_cart_session()

    def __iter__(self):
        product_ids = self.cart.keys()
        products = Product.objects.filter(id__in=product_ids)
        cart = self.cart.copy()
        for product in products:
            product_dict = model_to_dict(product)
            del product_dict["image"] # not needed in cart
            cart[str(product.id)]['product'] = product_dict
        for item in cart.values():
            item['total_price'] = int(item['price']) * int(item['quantity'])
            yield item

    def __str__(self):
        copy_cart = self.cart.copy()
        for id in copy_cart:
            del copy_cart[id]["product"]
        return str(copy_cart)

    def add_cart_session(self):
        cart = self.session.get(CART_SESSION_ID)
        if cart is None:
            cart = self.session[CART_SESSION_ID] = {}
        return cart

    def add(self, product, quantity):
        product_id = str(product.id)

        if product_id not in self.cart:
            self.cart[product_id] = {'quantity': 0, 'price': str(product.price)}

        self.cart.get(product_id)['quantity'] += quantity
        self.save()

    def remove(self, product):
        product_id = str(product.id)
        if product_id in self.cart:
            del self.cart[product_id]
            self.save()

    def update(self, product_id, quantity):
        if product_id in self.cart:
            self.cart[product_id]['quantity'] = quantity
            self.save()

    def show_quantity(self, product_id):
        if product_id in self.cart:
            return self.cart[product_id]['quantity']
        return 0

    def save(self):
        self.session.modified = True

    def get_total_price(self):
        return sum(int(item['price']) * item['quantity'] for item in self.cart.values())

    def clear(self):
        del self.session[CART_SESSION_ID]
        self.save()