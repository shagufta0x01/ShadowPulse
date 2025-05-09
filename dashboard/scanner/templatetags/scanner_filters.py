from django import template

register = template.Library()

@register.filter
def split(value, arg):
    """Split a string by the given argument."""
    return value.split(arg)

@register.filter
def get_item(value, key):
    """
    Get an item from a list by index or from a dictionary by key.

    Usage:
        {{ my_list|get_item:0 }}
        {{ my_dict|get_item:'key' }}
    """
    try:
        # Try to use as a list index
        return value[int(key)]
    except (IndexError, ValueError, TypeError):
        try:
            # Try to use as a dictionary key
            return value.get(key, value.get(str(key), ''))
        except (AttributeError, TypeError):
            return ''

@register.filter
def trim(value):
    """Trim whitespace from a string."""
    if value:
        return value.strip()
    return ''
