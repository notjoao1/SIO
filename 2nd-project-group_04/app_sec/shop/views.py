from django.db.utils import IntegrityError

from django.shortcuts import render, redirect, get_object_or_404
from django.contrib import messages
from django.core.paginator import Paginator, PageNotAnInteger, EmptyPage
from online_shop.decorators import verified_required, no_auth_required
from shop.forms import ReviewForm
from shop.models import Product, Category, Review
from cart.forms import QuantityForm
from django_ratelimit.decorators import ratelimit


def paginat(request, list_objects):
    p = Paginator(list_objects, 20)
    page_number = request.GET.get('page')
    try:
        page_obj = p.get_page(page_number)
    except PageNotAnInteger:
        page_obj = p.page(1)
    except EmptyPage:
        page_obj = p.page(p.num_pages)
    return page_obj


def get_ordered_products_context(request, products):
    if "order_by" in request.GET:

        order_by = request.GET["order_by"]
        if order_by == 'Date, oldest':
            products = products.reverse()
        elif order_by == 'Alphabetically, A-Z':
            products = products.order_by("title")
        elif order_by == 'Alphabetically, Z-A':
            products = products.order_by("-title")
        elif order_by == 'Price, cheaper':
            products = products.order_by("price")
        elif order_by == 'Price, costlier':
            products = products.order_by("-price")
    else:
        order_by = 'Date, newest'
    return {'products': paginat(request, products), 'order_by': order_by}


@ratelimit(key='ip', rate='20/m', block=True)
@no_auth_required
def home_page(request):
    products = Product.objects.filter(quantity__gte=1)
    context = get_ordered_products_context(request, products)
    return render(request, 'home_page.html', context)


@ratelimit(key='ip', rate='15/m', block=True)
@verified_required
def product_detail(request, slug):
    product = get_object_or_404(Product, slug=slug)
    related_products = Product.objects.filter(category=product.category).all()[:5]
    context = {
        'title': product.title,
        'product': product,
        'QuantityForm': QuantityForm(),
        'favorites': 'favorites',
        'related_products': related_products,
        'reviews': product.review_set.all(),
    }

    if request.method == 'POST':
        review_form = ReviewForm(request.POST, request.FILES)
        if review_form.is_valid():
            rating = review_form.cleaned_data["rating"]
            review = review_form.cleaned_data["review"]
            user_review_image = request.FILES.get("user_review_image")
            try:
                r = Review(rating=rating, review=review, product=product, user_review_image=user_review_image,
                           user=request.user)
                r.save()
            except IntegrityError as e:
                # If user has already done a review
                context["ReviewFormErrors"] = ["You have already reviewed this product. You can't do it again!"]
            context["ReviewForm"] = ReviewForm()
        else:
            context["ReviewForm"] = ReviewForm(initial={'review': review_form.cleaned_data["review"]})
            user_review_image_error = review_form.errors.get('user_review_image')
            context[
                "ReviewFormErrors"] = user_review_image_error if user_review_image_error else review_form.errors.get(
                '__all__')
    else:
        context["ReviewForm"] = ReviewForm()

    if request.user.likes.filter(id=product.id).first():
        context['favorites'] = 'remove'
    return render(request, 'product_detail.html', context)


@ratelimit(key='ip', rate='20/m', block=True)
@verified_required
def add_to_favorites(request, product_id):
    product = get_object_or_404(Product, id=product_id)
    request.user.likes.add(product)
    return redirect('shop:product_detail', slug=product.slug)


@verified_required
def remove_from_favorites(request, product_id):
    product = get_object_or_404(Product, id=product_id)
    request.user.likes.remove(product)
    return redirect('shop:favorites')


@ratelimit(key='ip', rate='30/m', block=True)
@verified_required
def favorites(request):
    products = request.user.likes.all()
    context = {'title': 'Favorites', 'products': products}
    return render(request, 'favorites.html', context)


@ratelimit(key='ip', rate='30/m', block=True)
@no_auth_required
def search(request):
    query = request.GET.get('q')

    if len(query) > 64:
        messages.error(request, "Search length must be shorter or equal to 64.", 'danger')
        products = Product.objects.filter(quantity__gte=1)
        context = get_ordered_products_context(request, products)
        return render(request, 'home_page.html', context)

    products = Product.objects.raw('SELECT * FROM shop_product WHERE shop_product.title LIKE %s', ['%' + query + '%'])
    context = {'products': products, 'search': query}
    return render(request, 'home_page.html', context)


@ratelimit(key='ip', rate='30/m', block=True)
@no_auth_required
def filter_by_category(request, slug):
    """when user clicks on parent category
	we want to show all products in its sub-categories too
	"""
    # slug is unique so we can use get
    category = Category.objects.get(slug=slug)
    result = Product.objects.filter(quantity__gte=1, category__in=category.get_all_categories())
    context = get_ordered_products_context(request, result)
    return render(request, 'home_page.html', context)


@ratelimit(key='ip', rate='30/m', block=True)
@verified_required
def delete_review(request, id):
	review = Review.objects.filter(id=id).delete()
	messages.success(request, 'Review has been deleted!', 'success')
	return redirect(request.META.get('HTTP_REFERER', 'redirect_if_referer_not_found'))
