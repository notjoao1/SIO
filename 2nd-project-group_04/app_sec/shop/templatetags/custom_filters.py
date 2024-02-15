from django import template

register = template.Library()


@register.filter(name='range_int')
def range_int(length):
    return range(1, length + 1)

