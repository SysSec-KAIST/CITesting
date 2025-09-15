import csv 
import os
import argparse

def parse_log_file_updated(file_path):
    with open(file_path, 'r', encoding='utf-8') as file:
        lines = file.readlines()

    # State variables
    test_section_started = False
    verify_section_started = False
    first_test_section = True
    write_test_response_message = False
    current_row = []

    for line in lines:
        line = line.strip()

        # Detect the start of the test attach section
        if "******************* Test Attach *******************" in line:
            test_section_started = True
            verify_section_started = False
            if current_row:
                # Append the existing row and start a new one
                current_row = []
            continue

        # Detect the start of the verify attach section
        if "******************* Verify Attach *******************" in line:
            current_row.append(' ') 
            current_row.append('Verify -->')
            verify_section_started = True
            test_section_started = False
            continue

        # Parse the test attach section
        if test_section_started:
            if "---------- Test Configuration ----------" in line:
                write_test_response_message = False
                if not first_test_section:
                    current_row.append(' ')
                continue  # Skip the marker line

            if first_test_section and ':' in line and "[UE -> NAS]" not in line and "[UE <- NAS]" not in line:
                key, value = map(str.strip, line.split(':', 1))
                current_row.append(value)
            elif line.endswith('.conf'):
                current_row.append(os.path.basename(line))  # Only save the file name
            
 
            # Include the first "[UE -> NAS]" or "[UE <- NAS]" line only
            if not write_test_response_message and ("[UE -> NAS]" in line or "[UE <- NAS]" in line):
                first_test_section = False
                message = line.split(': ')[1]
                if "[UE <- NAS]" in line:
                    write_test_response_message = True
                current_row.append(message)
        
        # Parse the verify attach section
        if verify_section_started:
            if ("[UE -> NAS]" in line or "[UE <- NAS]" in line):
                message = line.split(': ')[1]
                current_row.append(message)
                # break  # Only the first occurrence is needed

    return current_row

 

def parse_multiple_logs_with_append(directory_path, output_csv_path):
    data_rows = []  

    for file_name in os.listdir(directory_path):
        file_path = os.path.join(directory_path, file_name)

        if not os.path.isfile(file_path):  
            continue

        parsed_row = parse_log_file_updated(file_path)
        if parsed_row:  
            data_rows.append(parsed_row)

    # Write all accumulated rows to a single CSV file
    with open(output_csv_path, 'w', newline='', encoding='utf-8') as csv_file:
        writer = csv.writer(csv_file)
        # Write headers based on the maximum length of data rows
        max_columns = max(len(row) for row in data_rows)
        headers = [f"Column {i+1}" for i in range(max_columns)]
        writer.writerow(headers)
        writer.writerows(data_rows)

def ensure_parent_directory(file_path):
    parent_dir = os.path.dirname(file_path)
    
    if not os.path.exists(parent_dir):
        os.makedirs(parent_dir)

if __name__ == "__main__":
    arg_parser = argparse.ArgumentParser(description="This script parses log file and converts it into csv format")
    arg_parser.add_argument('-i', '--input_log_path', required=True, help="path of log file directory")    
    arg_parser.add_argument('-o', '--output_csv_path', required=True, help="path of csv file")    
    args = arg_parser.parse_args()

    input_log_path = args.input_log_path
    output_csv_path = args.output_csv_path

    ensure_parent_directory(output_csv_path)
    parse_multiple_logs_with_append(input_log_path, output_csv_path)
