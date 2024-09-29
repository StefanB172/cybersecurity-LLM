from django import template

register = template.Library()

@register.filter(name='prettify_java_code')
def prettify_java_code(value):
    formatted = value.replace(';', ';\n')
    formatted = formatted.replace('{', '{\n')
    formatted = formatted.replace('}', '\n}')

    # Split the formatted string into lines
    lines = formatted.split('\n')
    
    # Remove empty or whitespace-only lines
    filtered_lines = [line for line in lines if line.strip()]
    
    # Join the remaining lines back into a single string
    final_output = '\n'.join(filtered_lines)
    return final_output

@register.filter(name='csv_to_new_line')
def csv_to_new_line(value):
    formatted = value.replace(',', ',\n')
    return formatted
