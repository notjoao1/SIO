import os

from django.conf import settings
from accounts.models import User
from .models import Order
from django.shortcuts import get_object_or_404

def create_invoice(order_id : int):
    # create file_content
    try:
        order = get_object_or_404(Order, id=order_id)
        user = get_object_or_404(User, id=order.user.id)
    except:
        return
    file_content = "\tDETI MERCH SHOP - ORDER {}\nOrdered by - {} ({})\n\nProducts:\n{:25s} {:20s} {:12s}\n\n".format(order_id, user.full_name, user.email, "Product name", "Price x Quantity", "Total Price")

    for item in order.items.all():
        file_content += "{:25s} {:20s} {:12d}\n".format(item.product.title, str(item.price) + " x " + str(item.quantity), int(item.price) * int(item.quantity))

    file_content += "\nDate: {}".format(order.created)


    # check if /media/invoice exists, and create if not
    inv_path = os.path.join(settings.MEDIA_ROOT, "invoices")
    if not os.path.exists(inv_path):
        os.mkdir(inv_path)
    file_name = f"{order_id}.txt"
    file_path = os.path.join(inv_path, file_name)
    f = open(file_path, 'w')
    f.write(file_content)
    print(f"Invoice file {order_id}.txt successfully saved.")
    