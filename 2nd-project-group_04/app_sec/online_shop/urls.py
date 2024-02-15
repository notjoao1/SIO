import os

from django.contrib import admin
from django.urls import path, include, re_path
from django.conf import settings
from django.conf.urls.static import static
from django.views.static import serve

from online_shop.decorators import no_access, no_auth_required
from django.urls import URLResolver, URLPattern

urlpatterns = [
    path('', include('shop.urls', namespace='shop')),
    path('accounts/', include('accounts.urls', namespace='accounts')),
    path('cart/', include('cart.urls', namespace='cart')),
    path('orders/', include('orders.urls', namespace='orders')),
    path('dashboard/', include('dashboard.urls', namespace='dashboard')),
]

for pat in urlpatterns:
    # print("PAT: ", pat)
    if isinstance(pat, URLPattern):
        pat.callback = no_access(pat.callback)
    else:
        for subpat in pat.url_patterns:
            # print(subpat)
            # no nested subpatterns
            subpat.callback = no_access(subpat.callback)

# To serve files with DEBUG = False
urlpatterns += [
    # serve all static files
    re_path(r'^static/(?P<path>.*)$', serve, {'document_root': settings.STATIC_ROOT}),

    # serve only public media files
    # serve all product files (images of each product)
    re_path(r'^media/products/(?P<path>.*)$', serve, {'document_root': os.path.join(settings.MEDIA_ROOT, 'products')}),
    # serve all review images (reviews are made so everyone can see the review)
    re_path(r'^media/review_images/(?P<path>.*)$', serve, {'document_root': os.path.join(settings.MEDIA_ROOT, 'review_images')}),
    # no need to serve invoices because they are downloaded manually at a specific endpoint
    # at that endpoint we only allow the corresponding user to download the invoice
]

if settings.DEBUG:
    urlpatterns += [
        path('admin/', admin.site.urls)
    ]
