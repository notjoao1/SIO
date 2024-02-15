from django.db import models
from django.urls import reverse
from django.template.defaultfilters import slugify
# from accounts.models import User


class Category(models.Model):
    title = models.CharField(max_length=200)
    super_category = models.ForeignKey(
        'self', on_delete=models.CASCADE,
        related_name='sub_categories', null=True, blank=True
    )
    slug = models.SlugField(max_length=200, unique=True)

    def __str__(self):
        return self.title

    # root category has level 0
    @property
    def level(self):
        if self.super_category:
            return 1 + self.super_category.level
        return 0

    def has_parent(self):
        if self.super_category:
            return True
        return False

    def has_children(self):
        if self.sub_categories.all():
            return True
        return False

    def get_all_categories(self):
        all_categories = [self]
        for sc in all_categories[0].sub_categories.all():
            if sc.has_children():
                all_categories += sc.get_all_categories()
            else:
                all_categories.append(sc)
        return all_categories

    def get_absolute_url(self):
        return reverse('shop:product_detail', kwargs={'slug':self.slug})

    def save(self, *args, **kwargs): # new
        self.slug = slugify(self.title)
        return super().save(*args, **kwargs)
        

class Product(models.Model):
    category = models.ForeignKey(Category, on_delete=models.CASCADE, related_name='category')
    image = models.ImageField(upload_to='products')
    title = models.CharField(max_length=250)
    quantity = models.IntegerField()
    description = models.TextField()
    price = models.IntegerField()
    date_created = models.DateTimeField(auto_now_add=True)
    slug = models.SlugField(unique=True)

    class Meta:
        ordering = ('-date_created',)

    def __str__(self):
        return self.slug
        
    def get_absolute_url(self):
        return reverse('shop:product_detail', kwargs={'slug':self.slug})

    def save(self, *args, **kwargs):
        self.slug = slugify(self.title)
        return super().save(*args, **kwargs)


class Review(models.Model):
    product = models.ForeignKey(Product, on_delete=models.CASCADE)
    # referred like this to avoid circular import
    user = models.ForeignKey('accounts.User', on_delete=models.CASCADE)
    review = models.CharField(max_length=2048)
    rating = models.IntegerField(default=3)
    created = models.DateTimeField(auto_now_add=True)
    user_review_image = models.ImageField(upload_to='product_images', null=True)

    class Meta:
        ordering = ['created']
        # User can only review one time each product
        unique_together = ('product','user')

