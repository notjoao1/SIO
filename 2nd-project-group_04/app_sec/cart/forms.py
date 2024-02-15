from django import forms


class QuantityForm(forms.Form):
    

    quantity = forms.IntegerField(label='',
        min_value=1, max_value=9999, widget=forms.NumberInput(
            attrs={'class': 'form-control mt-1','placeholder': 'quantity','value': 1}
        )
    )







    """ class QuantityForm(forms.Form):
    quantity = forms.IntegerField(label='',
        min_value=1, max_value=20, widget=forms.NumberInput(
            attrs={'class': 'form-control mt-1','placeholder': 'quantity'}
        )
    ) """