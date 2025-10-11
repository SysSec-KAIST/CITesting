import os
import configparser
import shutil
import argparse
import re

pair_adaptive_message = {'Authentication Request':['auth_response', 'auth_failure'], 'Attach Accept':['attach_complete'], 'Identity Request':['identity_response'], 'Security Mode Command':['security_mode_complete', 'security_mode_reject']}
pair_message = [set() for _ in range(100)]
           
def compare_from_verfication_log(test_log_file, depth):
   start_processing = False
  
   if state == "DEREGI" or state == "IDLE":
      with open(normal_response_path) as file:
         file_lines = file.readlines()
         file.seek(0)
         normal_procedure_file_lines = file.readlines()
   
   lines_num = 0
   with open(test_log_file, 'r') as file:
      content = file.read()
      file.seek(0)
      file_lines = file.readlines()

      test_count = content.count("<TEST>")
      if state != "CONN" and ('Verify Attach' not in content):
         return "Fatal error"
      if ('Initial Attach' not in content) or ('Test Attach' not in content) or (test_count != depth):
         print("[Fatal error] log file write error({})".format(test_log_file))
         return "Fatal error"
      if state == "CONN":
         return "Normal"
      
      for idx, line in enumerate(file_lines):
         if 'Verify Attach' in line:
            start_processing = True
            continue
         
         if start_processing:
            if '-->' in line:
               continue
            if state == "DEREGI": # Verification procedure is "GUTI Attach Request" 
                if (normal_procedure_file_lines[lines_num].strip() in line.strip()) and (lines_num < len(normal_procedure_file_lines)):
                    lines_num += 1
                else:
                    return "Abnormal"   
                if lines_num == len(normal_procedure_file_lines): 
                    return "Normal"
            elif state == "IDLE": # Verification procedure is "Service Request"
               if "[UE -> NAS] Service Request" in line:
                  next_idx = idx + 1
                  while True:
                     if '-->' in file_lines[next_idx]:
                        next_idx += 1
                     else:
                        break
                  next_line = file_lines[next_idx]
                  if "Successfully" in next_line:
                     return "Normal"
                  else:
                     return "Abnormal"
                
def readLog(log_path, cur_depth, mode): 
   line_of_response_message = 0
   depth_counter = 1
   with open(log_path, 'r') as log:
      lines = log.readlines()
      for i in range(len(lines)): #For searching response of depth N "Test message"
         if '<TEST>' in lines[i]:
            if (depth_counter == cur_depth):
                  while True:
                    if '-->' not in lines[i+1]:
                       break
                    else:
                       i = i+1    
                  line_of_response_message = i + 1
                  break
            else:
               depth_counter += 1
      if "Reject" in lines[line_of_response_message] or "no longer connected" in lines[line_of_response_message] or "No response" in lines[line_of_response_message]:
         return 

      if mode == "cur_depth":
         gen_cur_depth_adaptive_config(log_path, cur_depth, lines[line_of_response_message])
      elif mode == "next_depth":
         gen_next_state_config(log_path, cur_depth, lines[line_of_response_message]) # generate next state message sequence
      
def gen_next_state_config(log_filename, depth, response_message): # New Version
   cwd = os.path.dirname(os.path.realpath(__file__))
   match = re.search(r'depth(\d)+_(\d+_\d+)\.log', log_filename)
   if match:
      test_num = int(match.group(1))
      print("test_num: ", test_num)
      file_index = match.group(2)
      front_index = file_index.split('_')[0]
   
   depth_count = 0
   start_processing = False
   with open(log_filename, 'r') as file:
      file_lines = file.readlines()

      for line in file_lines:
         if 'Test Attach' in line:
            start_processing = True
            continue
         
         if start_processing:
            if '-->' in line:
               continue
            if '[UE -> NAS] <TEST>' in line:
               depth_count += 1
               if depth_count == test_num:
                  test_message = line.split('[UE -> NAS] <TEST> ')[1]
            if '[UE <- NAS]' in line:
               if depth_count == test_num:
                  response_message = line.split('[UE <- NAS] ')[1]
                  break
      pair = (test_message, response_message)
      print(pair)
      if pair not in pair_message[int(front_index)]:
         source_config = f'./data/{core}/test_list/{core}_depth{depth}_{state}_{initial_message_type}/depth{depth}_{file_index}.conf'
         destination_config = f'./data/{core}/test_list/{core}_depth{depth}_{state}_{initial_message_type}_merged/depth{depth}_{sum(len(s) for s in pair_message)}.conf'
         shutil.copy2(source_config, destination_config)
         config_test_list_parser = configparser.ConfigParser()
         config_test_list_parser[str(sum(len(s) for s in pair_message))] = {} #remove first 'underscore'
         config_test_list_parser[str(sum(len(s) for s in pair_message))]['test_file'] = cwd + f"/data/{core}/test_list/{core}_depth{depth}_{state}_{initial_message_type}_merged/depth{depth}_{sum(len(s) for s in pair_message)}.conf"
         config_test_list_parser[str(sum(len(s) for s in pair_message))]['logfile'] =  cwd + f"/data/{core}/log/{core}_depth{depth}_{state}_{initial_message_type}_merged/depth{depth}_{sum(len(s) for s in pair_message)}.log"
         with open(f'./data/{core}/config/{core}_depth{depth}_{state}_{initial_message_type}_merged/test_list_depth{depth}.conf', 'a') as testconfFile: #write new test list for next depth
            config_test_list_parser.write(testconfFile)
         pair_message[int(front_index)].add((test_message, response_message))

def gen_cur_depth_adaptive_config(log_filename, depth, response_message): # New Version
   cwd = os.path.dirname(os.path.realpath(__file__))
   match = re.search(r'depth\d+_(\d+)\.log', log_filename)
   if match:
      file_index = match.group(1)
   next_depth_testlist_directory = f"./data/{core}/test_list/{core}_depth{depth+1}_{state}_{initial_message_type}"
   if not os.path.exists(next_depth_testlist_directory):
      os.makedirs(next_depth_testlist_directory)
   for resp, pair_resp in pair_adaptive_message.items():
      if resp in response_message:
         pair_response = pair_resp
         break
   next_depth_count = 0
   for i in range(len(pair_response)):
      num_of_test_message = calcNumOfTestMessage(pair_response[i])
      for j in range(0, num_of_test_message):
         if depth == 1:
            source_config = f'./data/{core}/test_list/{core}_depth{depth}_{state}_{initial_message_type}/depth{depth}_{file_index}.conf'
         else:   
            source_config = f'./data/{core}/test_list/{core}_depth{depth}_{state}_{initial_message_type}_merged/depth{depth}_{file_index}.conf'
         destination_config = f'./data/{core}/test_list/{core}_depth{depth+1}_{state}_{initial_message_type}/depth{depth+1}_{file_index}_{next_depth_count+j}.conf'
         message = cwd + f"/data/message/{pair_response[i]}/{pair_response[i]}_{j}.conf"
         copy_and_append_config(source_config, destination_config,'lte', message)
         config_test_list_parser = configparser.ConfigParser()
         config_test_list_parser[str(file_index)+'_'+str(next_depth_count+j)] = {} #remove first 'underscore'
         config_test_list_parser[str(file_index)+'_'+str(next_depth_count+j)]['test_file'] = cwd + f"/data/{core}/test_list/{core}_depth{depth+1}_{state}_{initial_message_type}/depth{depth+1}_{file_index}_{next_depth_count+j}.conf"
         config_test_list_parser[str(file_index)+'_'+str(next_depth_count+j)]['logfile'] =  cwd + f"/data/{core}/log/{core}_depth{depth+1}_{state}_{initial_message_type}/depth{depth+1}_{file_index}_{next_depth_count+j}.log"
         with open(f'./data/{core}/config/{core}_depth{depth+1}_{state}_{initial_message_type}/test_list_depth{depth+1}.conf', 'a') as testconfFile: #write new test list for next depth
            config_test_list_parser.write(testconfFile)
      next_depth_count += num_of_test_message
      
#parm 'depth' is target depth
def parseFileIndex(filename, depth):
   split_file_list = filename.split('_')
   index = ''
   for i in range(depth-1):
      index += '_{}'.format(split_file_list[i+1])
   return index

def calcNumOfTestMessage(test_directory):
   directory_path = f"./data/message/" + test_directory
   all_items = os.listdir(directory_path)
   files_only = [item for item in all_items if os.path.isfile(os.path.join(directory_path, item))]
   return len(files_only)

def copy_and_append_config(source_config_path, destination_config_path, section, test_message):
   shutil.copyfile(source_config_path, destination_config_path)
   destination_config = configparser.ConfigParser()
   
   destination_config['lte'] = {}
   destination_config[section]['name'] = test_message
   with open(destination_config_path, 'a') as configfile:
      destination_config.write(configfile)

if __name__ == "__main__":
   arg_parser = argparse.ArgumentParser(description="This script parses previous depth level log and compares with newly generated log")
   arg_parser.add_argument('-l', '--log_path', required=True, help="path of log file directory(must end with '/')")
   arg_parser.add_argument('-b', '--baseline_log', required=True, help="path of previous depth normal attach procedure log(must end with '/' if path is directory)")
   arg_parser.add_argument('-i', '--initial_message_type', required=True, help="message type of initial message")
   arg_parser.add_argument('-c', '--core', required=True, help="name of core network [amari, srsran, open5gs, nextepc]")
   arg_parser.add_argument('-s', '--state', required=True, help="state of UE and core [DEREGI, CONN, IDLE]")
   arg_parser.add_argument('-m', '--mode', required=True, help="mode of log file")
   args = arg_parser.parse_args()

   file_path = args.log_path
   normal_response_path = args.baseline_log
   initial_message_type = args.initial_message_type
   core = args.core
   state = args.state
   abnormal = 0
   normal = 0
   fatal = 0

   CIV_category = False
   if "merged" not in file_path:
      CIV_category = True

   depth_match = re.search(r'_depth(\d+)', file_path)
   if depth_match:
      depth_number = int(depth_match.group(1))
      print(f"Depth number: {depth_number}")
   cur_log_depth = depth_number
   print("Current log depth: {}".format(cur_log_depth))

   next_depth_dir = [f'./data/{core}/config/{core}_depth{cur_log_depth+1}_{state}_{initial_message_type}_merged/', f'./data/{core}/log/{core}_depth{cur_log_depth+1}_{state}_{initial_message_type}_merged/', f'./data/{core}/log/{core}_depth{cur_log_depth+1}_{state}_{initial_message_type}_merged/execution_list/', f'./data/{core}/test_list/{core}_depth{cur_log_depth+1}_{state}_{initial_message_type}_merged']
   cur_depth_testing_dir = [f'./data/{core}/config/{core}_depth{cur_log_depth+1}_{state}_{initial_message_type}', f'./data/{core}/log/{core}_depth{cur_log_depth+1}_{state}_{initial_message_type}', f'./data/{core}/log/{core}_depth{cur_log_depth+1}_{state}_{initial_message_type}/execution_list/', f'./data/{core}/test_list/{core}_depth{cur_log_depth+1}_{state}_{initial_message_type}']
   for dir in next_depth_dir+cur_depth_testing_dir:
      if not os.path.exists(dir):
         print(f"[os] makedir {dir}")
         os.makedirs(dir)

   next_depth_config_testlist = f'./data/{core}/config/{core}_depth{cur_log_depth+1}_{state}_{initial_message_type}_merged/test_list_depth{cur_log_depth+1}.conf'
   if os.path.exists(next_depth_config_testlist):
      with open(next_depth_config_testlist, 'w') as file:
         file.truncate(0)

   if CIV_category:
      # make directory for copying normal case log file
      full_path = os.path.join(file_path, f'../{core}_depth{cur_log_depth}_{state}_{initial_message_type}_normal')
      normal_dir = os.path.normpath(full_path)
      if not os.path.exists(normal_dir):
         os.makedirs(normal_dir)

      # make directory for copying abnormal case log file
      full_path = os.path.join(file_path, f'../{core}_depth{cur_log_depth}_{state}_{initial_message_type}_abnormal')
      abnormal_dir = os.path.normpath(full_path)
      if not os.path.exists(abnormal_dir):
         os.makedirs(abnormal_dir)

      # make directory for copying fatal error case log file
      full_path = os.path.join(file_path, f'../{core}_depth{cur_log_depth}_{state}_{initial_message_type}_fatal_error')
      fatal_error_dir = os.path.normpath(full_path)
      if not os.path.exists(fatal_error_dir):
         os.makedirs(fatal_error_dir)

   # compare log file with normal attach procedure and generate next depth config file
   for file in os.listdir(file_path):
      if not file.startswith("depth"):
         continue
      ret_code = "init"
      testing_message_num = file.count("_") # if file is testing procedure, this value is 2
      full_path = os.path.join(file_path, file)
      
      ret_code = compare_from_verfication_log(full_path, cur_log_depth) # If testing procedure, add one to depth number
      if ret_code == "Abnormal":
         readLog(full_path, cur_log_depth, args.mode)
         abnormal += 1
         if CIV_category:
            shutil.copy(full_path, abnormal_dir)
      elif ret_code == "Normal":
         readLog(full_path, cur_log_depth, args.mode)
         normal += 1
         if CIV_category:
            shutil.copy(full_path, normal_dir)
      elif ret_code == "Fatal error":
         fatal += 1
         if CIV_category:
            shutil.copy(full_path, fatal_error_dir)
            
   print("Abnormal: {}".format(abnormal))
   print("Normal: {}".format(normal))
   print("Fatal error: {}".format(fatal))
   