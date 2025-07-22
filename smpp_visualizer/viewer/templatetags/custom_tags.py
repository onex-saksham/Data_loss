from django import template

register = template.Library()

@register.filter(name='getattr')
def getattr_filter(obj, attr):
    return getattr(obj, attr, '')
