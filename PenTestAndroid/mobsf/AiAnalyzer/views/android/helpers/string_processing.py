import Levenshtein as lev

def parse_raw_strings(input_file_path, output_file_path, is_log_file):
    # Define the input and output file paths

    processed_lines = set()  # Use a set to avoid duplicates

    if is_log_file:
        with open(input_file_path, 'r') as file:
            for line in file:
                parts = line.split()  # Split the line into parts
                if len(parts) > 4:
                    new_line = ' '.join(parts[4:])  # Rejoin parts, skipping the first three
                    processed_lines.add(new_line + '\n')  # Add to set to remove duplicates
    else:
        with open(input_file_path, 'r') as file:
            for line in file:
                processed_lines.add(line)  # Add to set to remove duplicates 

    # Write the processed lines to a new file
    with open(output_file_path, 'w') as outfile:
        final_lines = []
        for line in processed_lines:
            if all(not are_similar(line, existing_line) for existing_line in final_lines):
                final_lines.append(line)
        for line in final_lines:
            outfile.write(line)

def are_similar(str1, str2, threshold=0.9):
    """Check if two strings are similar above a specified threshold."""
    distance = lev.distance(str1, str2)
    max_len = max(len(str1), len(str2))
    similarity = 1 - (distance / max_len)
    return similarity > threshold