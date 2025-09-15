import subprocess
import time
import os
import configparser
import argparse
import socket
import re
from pathlib import Path
import sys

TIMEOUT = 40
    
def send_and_wait(sock, message, proc): # There can be 3 error
    sock.settimeout(TIMEOUT)
    sock.sendall(message.encode())
    try:
        reply = sock.recv(1024).decode()
        if not reply:
            print("Connection close")
            return True
        print(f"Received reply: {reply}")

        if reply == "Finish":
            return True, reply
        else:
            return False, reply

    except socket.timeout:
        print(f"There is no signal during {TIMEOUT} seconds")
        return True, "timeout"
    except BrokenPipeError:
        print("BrokenPipeError: The connection was lost.")
        return True, "brokenPipe"  # Handle broken pipe case explicitly

    except Exception as e:
        print(f"Unexpected error: {e}")
        return True, "unexpectedError"  # Handle other exceptions explicitly
    
def find_free_port(starting_port):
    port = starting_port
    while True:
        print(f"Searching...(port: {port})")
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            if s.connect_ex(('localhost', port)) != 0:
                return port
            port += 2

def increment_depth_string(input_string):
    pattern = r'(_depth)(\d+)'

    def increase_number(match):
        return f"{match.group(1)}{int(match.group(2)) + 1}"
    
    updated_string = re.sub(pattern, increase_number, input_string)
    return updated_string

def ensure_directory_exists(file_path):
    parent_dir = Path(file_path).parent

    if not parent_dir.exists():
        parent_dir.mkdir(parents=True, exist_ok=True)
        execution_list_dir = 'execution_list'
        os.makedirs(os.path.join(parent_dir, execution_list_dir))

def sort_conf_files(directory):
    file_list = [f for f in os.listdir(directory) if f.endswith('.conf')]
    
    def extract_number(filename):
        match = re.search(r'_(\d+)\.conf$', filename)
        return int(match.group(1)) if match else float('inf')
    
    return sorted(file_list, key=extract_number)

def check_interface(interface_name):
    try:
        result = subprocess.run(["ip", "link", "show", interface_name], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return result.returncode == 0
    except subprocess.CalledProcessError:
        print("[Fatal Error] ================ No interface ================")
        return False

def check_file_content(filepath):
    if os.path.exists(filepath):
        with open(filepath, 'r') as file:
            content = file.read()
            if content.strip():
                print(f"Content found in {filepath}: {content.strip()}")
            else:
                print(f"No content found in {filepath}.")

        os.remove(filepath)
        print(f"File {filepath} deleted.")
        return True
    
    else:
        print(f"{filepath} does not exist.")
        return False

def execute_test(config_dir, state, port_offset):
    files = sort_conf_files(config_dir)
    print(files)
        
    if not files: # if there is no test list, break
        return

    for file in files:
        victim_port = find_free_port(int(args.victim_port)+port_offset)
        attacker_port = find_free_port(int(args.attacker_port)+port_offset)
            
        if state == "CONN":
            path_name = os.path.basename(os.path.normpath(config_dir))
            target_dir = os.path.join('./ping_detection', path_name)
            os.makedirs(target_dir, exist_ok=True)
            rrc_release_target_dir = os.path.join('./rrc_release_detection', path_name)
            os.makedirs(rrc_release_target_dir, exist_ok=True)
            path_name = os.path.basename(os.path.normpath(config_dir))
            target_dir = os.path.join('./ping_detection', path_name)
            error_dir = os.path.join(target_dir, 'fatal_error')
            os.makedirs(error_dir, exist_ok=True)

        if state == "DEREGI":
            victim_command = ["../build/srsue/src/srsue", "../build/srsue/src/ue_victim.conf", "--nas.verify_sr", "false", "--nas.testing_state", str(state), "--nas.controller_port", str(victim_port),"--nas.test_file", os.path.join(config_dir, file), '--nas.keep_attach', str(args.end)]
            attacker_command = ["../build/srsue/src/srsue", "../build/srsue/src/ue_attacker.conf", "--nas.verify_sr", "false","--nas.testing_state", str(state), "--nas.controller_port", str(attacker_port), "--nas.test_file", os.path.join(config_dir, file), '--nas.keep_attach', str(args.end)]
        else:
            victim_command = ["../build/srsue/src/srsue", "../build/srsue/src/ue_victim.conf", "--nas.verify_sr", "true", "--nas.testing_state", str(state), "--nas.controller_port", str(victim_port),"--nas.test_file", os.path.join(config_dir, file), '--nas.keep_attach', str(args.end)]
            attacker_command = ["../build/srsue/src/srsue", "../build/srsue/src/ue_attacker.conf", "--nas.verify_sr", "true", "--nas.testing_state", str(state), "--nas.controller_port", str(attacker_port), "--nas.test_file", os.path.join(config_dir, file), '--nas.keep_attach', str(args.end)]
        victim_proc = subprocess.Popen(victim_command, stdout=sys.stdout, stderr=sys.stderr, text=True, bufsize=1)
        attacker_proc = subprocess.Popen(attacker_command, stdout=sys.stdout, stderr=sys.stderr, text=True, bufsize=1)
        time.sleep(10)
        victim_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        victim_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        victim_socket.connect(("localhost", victim_port))

        attacker_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        attacker_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        attacker_socket.connect(("localhost", attacker_port))

        # Trace configuration sections number
        section_list = []
        config_list = configparser.ConfigParser()
        config_path = os.path.join(config_dir, file)
        config_list.read(config_path, encoding='utf-8')
        section_list.extend(config_list.sections())
        print("Section list: ", section_list)
        section_count = 0
        
        while True:
            init_ping_success = False
            if section_count >= len(section_list):
                break
            print("config file: ", file)
            print("Section Number: ", section_list[section_count])
            section_count += 1
                
            print("Controller is ready...")
                
            print("[Victim] Initial Attach")
            ret, reply = send_and_wait(victim_socket, "initial", victim_proc)
                
            if ret: # End of Victim Execution
                break
                
            if state == "CONN": # Check initial ping success 
                ping_count = int(reply.split("_")[1])
                if ping_count != 0:
                    print("Initial Attach] Ping Success")
                    init_ping_success = True
                else:
                    print("[ERROR] Initial Attach Ping Fail")
                time.sleep(1)

            print("[Attacker] Testing")
            if os.path.exists("/tmp/ping_test.txt"):
                os.remove("/tmp/ping_test.txt")

            ret, reply = send_and_wait(attacker_socket, "testing", attacker_proc)
            if ret:
                break
            time.sleep(1)


            print("[Victim] Verify")    
            if state == "CONN":
                exist_file = check_file_content("/tmp/ping_test.txt")
                if exist_file:
                    path_name = os.path.basename(os.path.normpath(config_dir))
                    target_dir = os.path.join('./rrc_release_detection', path_name)
                    file_path = os.path.join(target_dir, file)
                    with open(file_path, 'a') as f:
                        f.write(f"[ping_test.txt] RRC Release Detected: section[{section_list[section_count-1]}]\n") # Previous index of section

                ret, reply = send_and_wait(victim_socket, "Finish_Ping_Test", victim_proc)
                if ret:
                    break
                    
                ping_count = int(reply.split("_")[1])
                print("Testing ping count: ", ping_count)
                if ping_count == 0 and init_ping_success:
                    print("[Victim] Ping Fail")
                    print("[!!!] Attach Detection [!!!]")
                    path_name = os.path.basename(os.path.normpath(config_dir))
                    target_dir = os.path.join('./ping_detection', path_name)
                    file_path = os.path.join(target_dir, file)
                    with open(file_path, 'a') as f:
                        f.write(f"RRC Release Detected: section[{section_list[section_count-1]}]\n") # Previous index of section
                elif ping_count != 0 and init_ping_success:
                    print("[Victim] Ping Success Normal Sequence")
                else:
                    path_name = os.path.basename(os.path.normpath(config_dir))
                    target_dir = os.path.join('./ping_detection', path_name)
                    error_dir = os.path.join(target_dir, 'fatal_error')
                    file_path = os.path.join(error_dir, file)
                    with open(file_path, 'a') as f:
                        f.write(f"Fatal Error[{section_list[section_count-1]}]\n") # Previous index of section
                    print("[Ping] Fatal error")
                time.sleep(3) # for stable initial attach
                continue
            else: # AllIdle and ECMIdle state
                ret, reply = send_and_wait(victim_socket, "verify", victim_proc)
                if ret:
                    break
                time.sleep(1)

                # bp += 1
        print("Terminate process...")
        victim_socket.close()
        attacker_socket.close()
        victim_proc.terminate()
        attacker_proc.terminate()
        time.sleep(25)     

if __name__ == "__main__":
    arg_parser = argparse.ArgumentParser()
    arg_parser.add_argument('-e', '--end', action='store_false', help='End test in the last config file. Don\'t keep attach')
    arg_parser.add_argument('-tc', '--test_config', required=True, help='["dir"/"core"_depth"n"/]specify path of config list (end with "/")')
    arg_parser.add_argument('-vp', '--victim_port', default='10000')
    arg_parser.add_argument('-ap', '--attacker_port', default='20000')
    arg_parser.add_argument('-state', required=True, help="state of UE and core [DEREGI, CONN, IDLE]")
    arg_parser.add_argument('-c', '--core', required=True, help='name of core network [amari, srsran, open5gs, Nokia]')
    arg_parser.add_argument('-i', '--initial_message_type', required=True, help="message type of initial message")
    args = arg_parser.parse_args()

    section_list = []

    config_dir = args.test_config
    state = args.state

    port_offset = 0
    if state == "CONN":
        os.makedirs('./ping_detection', exist_ok=True)

    while True:
        log_path = config_dir.replace('config', 'log')
        if not os.path.exists(log_path):
            os.makedirs(log_path)
            print(f"Directory {log_path} created.")
            execution_list_dir = 'execution_list'
            os.makedirs(os.path.join(log_path, execution_list_dir))
        else:
            print(f"Directory {log_path} already exists.")
        
        print(" ## State Transition Execution ## ")
        time.sleep(1) #sleep before executing UE
        
        if not os.path.isdir(config_dir): # if there is no next depth config directory, break
            break
        
        execute_test(config_dir, state, port_offset)
        time.sleep(5) # sleep for waiting to execute log parser
        
        os.system(f"python3 log_parser.py -l {log_path} -b ./normal_response/normal_response_{state}.txt -i {args.initial_message_type} -c {args.core} -s {args.state} -m cur_depth")
        time.sleep(2)
        testing_config_dir = increment_depth_string(config_dir)
        port_offset += 2
        execute_test(testing_config_dir, state, port_offset)

        log_path = testing_config_dir.replace('config', 'log')
        os.system(f"python3 log_parser.py -l {log_path} -b ./normal_response/normal_response_{state}.txt -i {args.initial_message_type} -c {args.core} -s {args.state} -m next_depth") 
        config_dir = testing_config_dir.replace(f"{state}_{args.initial_message_type}", f"{state}_{args.initial_message_type}_merged")
        port_offset += 2
        time.sleep(5)