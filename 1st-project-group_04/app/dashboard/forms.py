from django import forms
from django.forms import ModelForm

from shop.models import Product, Category


class AddProductForm(ModelForm):
    class Meta:
        model = Product
        fields = ['category', 'image', 'quantity', 'title', 'description', 'price']

    def __init__(self, *args, **kwargs):
        super(AddProductForm, self).__init__(*args, **kwargs)
        for visible in self.visible_fields():
            visible.field.widget.attrs['class'] = 'form-control'


class AddCategoryForm(ModelForm):
    class Meta:
        model = Category
        fields = ['title', 'super_category']
    

    def __init__(self, *args, **kwargs):
        super(AddCategoryForm, self).__init__(*args, **kwargs)
        self.fields['super_category'].widget.attrs['class'] = 'form-control'
        self.fields['title'].widget.attrs['class'] = 'form-control'


class EditProductForm(ModelForm):
    class Meta:
        model = Product
        fields = ['category', 'image', 'quantity', 'title', 'description', 'price']

    def __init__(self, *args, **kwargs):
        super(EditProductForm, self).__init__(*args, **kwargs)
        for visible in self.visible_fields():
            visible.field.widget.attrs['class'] = 'form-control'