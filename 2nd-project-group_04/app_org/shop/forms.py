from django import forms


class ReviewForm(forms.Form):
    review = forms.CharField(label='',widget=forms.Textarea(
        attrs={'class': 'form-control', 'id': 'reviewProduct', 'rows': '4',
               'placeholder': "Your opinion on the product"}
    ))
    rating = forms.IntegerField(widget=forms.HiddenInput(
        attrs={'id': 'hiddenRating'},
    ))
    user_review_image = forms.ImageField(label='', required=False, widget=forms.FileInput(attrs={
        'class': 'form-control', 'style': 'width: 20%', 'id': 'imageReviewInput'
    }))

    def clean(self):
        cleaned_data = super().clean() # invoke parent_class
        comment = cleaned_data.get('review')
        rating = cleaned_data.get('rating')
        user_review_image = cleaned_data.get('user_review_image')
        if comment is None:
            raise forms.ValidationError("A comment about the product is required. Please tell us your opinion")
        if rating is None or rating == 0:
            raise forms.ValidationError("Rating is required. Please select a rating.")
        if user_review_image and user_review_image.size > 4*1024*1024:
            raise forms.ValidationError("Image is too large (> 4 MB)")

        return cleaned_data

