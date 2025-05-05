import html
import re

def format_command_output(output_text, command_name=None):
    """
    Format command output as professional HTML

    Args:
        output_text (str): The raw command output text
        command_name (str, optional): The name of the command

    Returns:
        str: HTML-formatted output
    """
    # If it's already HTML content, return it as is
    if output_text.strip().startswith('<!DOCTYPE html>') or output_text.strip().startswith('<html>'):
        return output_text

    # Check if it's a partial HTML fragment (table or div)
    if output_text.strip().startswith('<') and ('<table' in output_text or '<div' in output_text):
        return output_text

    # Detect the type of output and format accordingly
    if is_table_output(output_text):
        return format_table_output(output_text)
    elif is_key_value_output(output_text):
        return format_key_value_output(output_text)
    elif is_list_output(output_text):
        return format_list_output(output_text)
    else:
        return format_generic_output(output_text)

def is_table_output(text):
    """Check if the output appears to be a table with columns"""
    lines = text.strip().split('\n')

    # Need at least 3 lines for a table (header, separator, data)
    if len(lines) < 3:
        return False

    # Check for consistent spacing that would indicate columns
    # Look for header with multiple words separated by spaces
    header_line = lines[0]
    if not re.search(r'\s{2,}', header_line):
        # Also check for PowerShell-style tables with dashes under each column
        if len(lines) > 1 and re.match(r'^-+\s+-+', lines[1]):
            return True
        return False

    # Check if there's a separator line (----)
    separator_line = lines[1]
    if not re.match(r'^[-\s]+$', separator_line) and not re.match(r'^-+\s+-+', separator_line):
        return False

    return True

def is_key_value_output(text):
    """Check if the output appears to be key-value pairs"""
    lines = text.strip().split('\n')

    # Count lines with a colon
    colon_lines = sum(1 for line in lines if ':' in line)

    # If more than 50% of non-empty lines have colons, it's likely key-value
    non_empty_lines = sum(1 for line in lines if line.strip())
    if non_empty_lines > 0 and colon_lines / non_empty_lines > 0.5:
        return True

    return False

def is_list_output(text):
    """Check if the output appears to be a list of items"""
    lines = text.strip().split('\n')

    # Check for bullet points or numbered lists
    bullet_lines = sum(1 for line in lines if line.strip().startswith(('•', '-', '*', '1.', '2.')))

    # If more than 50% of non-empty lines start with bullets, it's likely a list
    non_empty_lines = sum(1 for line in lines if line.strip())
    if non_empty_lines > 0 and bullet_lines / non_empty_lines > 0.5:
        return True

    return False

def format_table_output(text):
    """Format table output as an HTML table"""
    lines = text.strip().split('\n')

    # Check if this is a PowerShell-style table (with dashes under each column)
    is_powershell_style = False
    if len(lines) > 1 and re.match(r'^-+\s+-+', lines[1]):
        is_powershell_style = True

    # Extract header line
    header_line = lines[0]

    # For PowerShell-style tables, find column positions based on dashes
    if is_powershell_style:
        separator_line = lines[1]
        column_positions = [0]

        # Find the end of each column by looking at the dash groups
        dash_groups = re.finditer(r'-+', separator_line)
        for match in dash_groups:
            column_positions.append(match.end() + 1)  # +1 to account for space after dashes
    else:
        # Determine column positions by looking at header spacing
        column_positions = [0]
        for match in re.finditer(r'\s{2,}', header_line):
            column_positions.append(match.end())

    # Extract column names
    column_names = []
    for i in range(len(column_positions)):
        if i < len(column_positions) - 1:
            column_names.append(header_line[column_positions[i]:column_positions[i+1]].strip())
        else:
            column_names.append(header_line[column_positions[i]:].strip())

    # Start building HTML table
    html_output = '<div class="table-responsive">'
    html_output += '<table class="table table-striped table-hover">'

    # Add header
    html_output += '<thead class="table-dark"><tr>'
    for name in column_names:
        html_output += f'<th>{html.escape(name)}</th>'
    html_output += '</tr></thead>'

    # Add body
    html_output += '<tbody>'

    # Skip header and separator lines
    start_line = 2
    for line in lines[start_line:]:
        if not line.strip() or line.strip().startswith('-'):
            continue

        html_output += '<tr>'

        # Extract cell values based on column positions
        for i in range(len(column_positions)):
            if i < len(column_positions) - 1:
                cell_value = line[column_positions[i]:column_positions[i+1]].strip()
            else:
                cell_value = line[column_positions[i]:].strip()

            html_output += f'<td style="word-break: break-word;">{html.escape(cell_value)}</td>'

        html_output += '</tr>'

    html_output += '</tbody></table></div>'

    return html_output

def format_key_value_output(text):
    """Format key-value output as an HTML definition list"""
    lines = text.strip().split('\n')

    html_output = '<div class="key-value-container">'
    html_output += '<dl class="row">'

    section_title = None

    for line in lines:
        line = line.strip()

        # Skip empty lines and separator lines
        if not line or line.startswith('-') or line.startswith('='):
            continue

        # Check if this is a section title (no colon, all caps or ends with colon)
        if ':' not in line and (line.isupper() or line.endswith(':')):
            if section_title:
                html_output += '</div>'  # Close previous section

            section_title = line.rstrip(':')
            html_output += f'<div class="section mt-4"><h5 class="section-title">{html.escape(section_title)}</h5>'
            continue

        # Process key-value pair
        if ':' in line:
            key, value = line.split(':', 1)
            html_output += f'<dt class="col-sm-4" style="font-weight: bold;">{html.escape(key.strip())}</dt>'
            html_output += f'<dd class="col-sm-8" style="word-break: break-word;">{html.escape(value.strip())}</dd>'
        else:
            # Just a line without a key-value structure
            html_output += f'<dd class="col-sm-12" style="word-break: break-word;">{html.escape(line)}</dd>'

    # Close last section if there was one
    if section_title:
        html_output += '</div>'

    html_output += '</dl></div>'

    return html_output

def format_list_output(text):
    """Format list output as an HTML list"""
    lines = text.strip().split('\n')

    # Determine if it's an ordered or unordered list
    has_numbers = any(re.match(r'^\d+\.', line.strip()) for line in lines)

    html_output = '<div class="list-container">'

    # Extract title if present (first line without bullet or number)
    title = None
    for i, line in enumerate(lines):
        if line.strip() and not re.match(r'^[•\-*\d\.]\s', line.strip()):
            title = line.strip()
            lines = lines[i+1:]  # Remove title from lines
            break

    if title:
        html_output += f'<h5 class="list-title">{html.escape(title)}</h5>'

    # Create the list
    if has_numbers:
        html_output += '<ol class="list-styled">'
    else:
        html_output += '<ul class="list-styled">'

    for line in lines:
        line = line.strip()
        if not line:
            continue

        # Remove bullet or number prefix
        cleaned_line = re.sub(r'^[•\-*\d\.]\s*', '', line)

        html_output += f'<li style="word-break: break-word;">{html.escape(cleaned_line)}</li>'

    if has_numbers:
        html_output += '</ol>'
    else:
        html_output += '</ul>'

    html_output += '</div>'

    return html_output

def format_generic_output(text):
    """Format generic output with basic styling"""
    # Add some basic styling to the pre tag
    html_output = '<div class="generic-output">'
    html_output += f'<pre class="p-3 bg-light border rounded" style="white-space: pre-wrap; word-wrap: break-word; max-height: 500px; overflow-y: auto;">{html.escape(text)}</pre>'
    html_output += '</div>'

    return html_output
