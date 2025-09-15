import itertools
import os
import configparser
import argparse

def gen_attach_request():
   if not os.path.exists('./data/message/attach_request'):
      os.makedirs('./data/message/attach_request')
   sht = ['plain', 'integrity']
   sqn = ['invalid', 'valid']
   attach_type = ['combined', 'emergency']
   mobile_identity = ['imsi_v', 'guti_v']
   security_algorithm = ['valid', 'invalid'] # valid: '0,1,2,3', invalid: '0'
   ksi = ['invalid','valid', '7']

   config = configparser.ConfigParser()
   config.read('./test_msg/test_attach_req.conf', encoding='utf-8')

   cases = list(itertools.product(*[sht, sqn, attach_type, mobile_identity, security_algorithm, ksi]))
   
   for i in range(len(cases)):   
      config['lte']['security_header_type'] = cases[i][0]
      config['lte']['sqn'] = cases[i][1]
      config['lte']['mac_value'] = 'zero'

      config['lte']['attach_type'] = cases[i][2]
      if(cases[i][2] == 'emergency'):
         config['lte']['esm_request_type'] = 'emergency'
      else:
         config['lte']['esm_request_type'] = 'initial'
      
      config['lte']['mobile_identity'] = cases[i][3]
      if('guti' in cases[i][2]):
         config['lte']['tmsi_status'] = 'valid'
         config['lte']['old_guti_type'] = 'native'
         config['lte']['ksi'] = 'valid'
      elif('imsi' in cases[i][2]):
         config['lte']['tmsi_status'] = 'no_present'
         config['lte']['old_guti_type'] = 'no_present'
         config['lte']['ksi'] = '7'

      if cases[i][4] == 'valid':
         config['lte']['eea'] = '0,1,2,3'
         config['lte']['eia'] = '0,1,2,3'
      elif cases[i][4] == 'invalid':
         config['lte']['eea'] = '0'
         config['lte']['eia'] = '0'

      config['lte']['ksi'] = cases[i][5]

      with open('./data/message/attach_request/attach_request_{}.conf'.format(i), 'w') as configfile:
         config.write(configfile)
   
   return len(cases)

def gen_detach_request():
   if not os.path.exists('./data/message/detach_request'):
      os.makedirs('./data/message/detach_request')
   sht = ['plain', 'integrity']
   sqn = ['invalid', 'valid']
   ksi = ['7', 'valid', 'invalid']
   mobile_identity = ['imsi_v', 'guti_v']
   detach_type = ['imsi', 'combined']
   switch_off = ['switch_off', 'normal_detach']
   
   config = configparser.ConfigParser()
   config.read('./test_msg/test_detach_req.conf', encoding='utf-8')
   
   cases = list(itertools.product(*[sht, sqn, ksi, mobile_identity, detach_type, switch_off]))

   for i in range(len(cases)):   
      config['lte']['security_header_type'] = cases[i][0]
      config['lte']['sqn'] = cases[i][1]
      config['lte']['mac_value'] = 'zero'

      config['lte']['ksi'] = cases[i][2]
      config['lte']['mobile_identity'] = cases[i][3]
      config['lte']['detach_type'] = cases[i][4]
      config['lte']['switch_off'] = cases[i][5]

      with open('./data/message/detach_request/detach_request_{}.conf'.format(i), 'w') as configfile:
         config.write(configfile)
   
   return len(cases)

def gen_TAU_request():
   if not os.path.exists('./data/message/tau_request'):
      os.makedirs('./data/message/tau_request')
   sht = ['plain', 'integrity']
   sqn = ['invalid', 'valid']
   update_type = ['ta', 'combined', 'combined_w_imsi', 'periodic']
   ksi = ['7', 'valid', 'invalid']
   old_guti = ['imsi_v', 'guti_v']

   config = configparser.ConfigParser()
   config.read('./test_msg/test_tau_request.conf', encoding='utf-8')

   cases = list(itertools.product(*[sht,sqn, update_type, ksi, old_guti]))

   for i in range(len(cases)):   
      config['lte']['security_header_type'] = cases[i][0]
      config['lte']['sqn'] = cases[i][1]
      config['lte']['mac_value'] = 'zero'

      config['lte']['update_type'] = cases[i][1]
      config['lte']['ksi'] = cases[i][2]
      config['lte']['old_guti'] = cases[i][3]

      with open('./data/message/tau_request/tau_request_{}.conf'.format(i), 'w') as configfile:
         config.write(configfile)
   return len(cases)

def gen_service_request():
   if not os.path.exists('./data/message/service_request'):
      os.makedirs('./data/message/service_request')
   sqn = ['invalid', 'valid']
   ksi = ['7', 'valid', 'invalid']

   config = configparser.ConfigParser()
   config.read('./test_msg/test_service_req.conf', encoding='utf-8')

   cases = list(itertools.product(*[sqn, ksi]))

   for i in range(len(cases)):   
      config['lte']['security_header_type'] = 'service_request'
      config['lte']['sqn'] = cases[i][0]
      config['lte']['mac_value'] = 'zero'
      config['lte']['ksi'] = cases[i][1]

      with open('./data/message/service_request/service_request_{}.conf'.format(i), 'w') as configfile:
         config.write(configfile)
   
   return len(cases)

def gen_attach_complete():
   if not os.path.exists('./data/message/attach_complete'):
      os.makedirs('./data/message/attach_complete')
   sht = ['plain', 'integrity']

   config = configparser.ConfigParser()
   config.read('./test_msg/test_attach_complete.conf', encoding='utf-8')

   for i in range(len(sht)):   
      config['lte']['security_header_type'] = sht[i]
      config['lte']['mac_value'] = 'zero'
      config['lte']['sqn'] = 'valid'

      with open('./data/message/attach_complete/attach_complete_{}.conf'.format(i), 'w') as configfile:
         config.write(configfile)

def gen_auth_failure():
   if not os.path.exists('./data/message/auth_failure'):
      os.makedirs('./data/message/auth_failure')
   sht = ['plain', 'integrity']
   emm_cause = ['mac_failure', 'synch_failure', 'unacceptable']

   config = configparser.ConfigParser()
   config.read('./test_msg/test_auth_failure.conf', encoding='utf-8')
   cases = list(itertools.product(*[sht, emm_cause]))

   for i in range(len(cases)):   
      config['lte']['security_header_type'] = cases[i][0]
      config['lte']['emm_cause'] = cases[i][1]
      if cases[i][1] == 'synch_failure':
         config['lte']['auth_fail_param'] = 'invalid'
      else:
         config['lte']['auth_fail_param'] = 'no_present'

      with open('./data/message/auth_failure/auth_failure_{}.conf'.format(i), 'w') as configfile:
         config.write(configfile)

def gen_auth_response():
   if not os.path.exists('./data/message/auth_response'):
      os.makedirs('./data/message/auth_response')
   sht = ['plain', 'integrity']

   config = configparser.ConfigParser()
   config.read('./test_msg/test_auth_response.conf', encoding='utf-8')

   for i in range(len(sht)):   
      config['lte']['security_header_type'] = sht[i]
      config['lte']['mac_value'] = 'zero'
      config['lte']['sqn'] = 'valid'

      with open('./data/message/auth_response/auth_response_{}.conf'.format(i), 'w') as configfile:
         config.write(configfile)

def gen_identity_response():
   if not os.path.exists('./data/message/identity_response'):
      os.makedirs('./data/message/identity_response')
   sht = ['plain', 'integrity']
   mobile_identity = ['imsi_v', 'tmsi_v', 'imeisv_v']

   config = configparser.ConfigParser()
   config.read('./test_msg/test_identity_response.conf', encoding='utf-8')
   cases = list(itertools.product(*[sht, mobile_identity]))

   for i in range(len(cases)):   
      config['lte']['security_header_type'] = cases[i][0]
      config['lte']['mobile_identity'] = cases[i][1]
      config['lte']['mac_value'] = 'zero'
      config['lte']['sqn'] = 'valid'

      with open('./data/message/identity_response/identity_response_{}.conf'.format(i), 'w') as configfile:
         config.write(configfile)

def gen_security_mode_complete():
   if not os.path.exists('./data/message/security_mode_complete'):
      os.makedirs('./data/message/security_mode_complete')
   sht = ['plain', 'integrity_and_cipher_w_new']
   mobile_identity = ['imsi_v', 'tmsi_v', 'imeisv_v']
   config = configparser.ConfigParser()
   config.read('./test_msg/test_security_mode_complete.conf', encoding='utf-8')
   cases = list(itertools.product(*[sht, mobile_identity]))

   for i in range(len(cases)):   
      config['lte']['security_header_type'] = cases[i][0]
      config['lte']['mobile_identity'] = cases[i][1]
      config['lte']['mac_value'] = 'zero'
      config['lte']['sqn'] = 'valid'

      with open('./data/message/security_mode_complete/security_mode_complete_{}.conf'.format(i), 'w') as configfile:
         config.write(configfile)

def gen_security_mode_reject():
   if not os.path.exists('./data/message/security_mode_reject'):
      os.makedirs('./data/message/security_mode_reject')
   sht = ['plain', 'integrity']
   emm_cause = ['sec_cap_mismatch', 'sec_mode_reject_unspecified']
   config = configparser.ConfigParser()
   config.read('./test_msg/test_security_mode_reject.conf', encoding='utf-8')
   cases = list(itertools.product(*[sht, emm_cause]))

   for i in range(len(cases)):   
      config['lte']['security_header_type'] = cases[i][0]
      config['lte']['emm_cause'] = cases[i][1]

      with open('./data/message/security_mode_reject/security_mode_reject_{}.conf'.format(i), 'w') as configfile:
         config.write(configfile)

def gen_tau_request_config(cases, core, state):
   cwd = os.path.dirname(os.path.realpath(__file__))
   test_list_dir = f'./data/{core}/test_list/{core}_depth1_{state}_tau'
   conf_dir = f'./data/{core}/config/{core}_depth1_{state}_tau'
   dir_list = [test_list_dir, conf_dir]
   for dir in dir_list:
      if not os.path.exists(dir):
            print(f"[os] makedir {dir}")
            os.makedirs(dir)

   test_list_config = configparser.ConfigParser()
   config_list = configparser.ConfigParser()
   config_list.read('./test_msg/test_list.conf', encoding='utf-8')
   for i in range(cases):
      config_list['lte']['name'] = cwd + f"/data/message/tau_request/tau_request_{i}.conf"
      with open(f'./data/{core}/test_list/{core}_depth1_{state}_tau/depth1_{i}.conf', 'w') as configfile:
         config_list.write(configfile)
      
      test_list_config[str(i)] = {}
      test_list_config[str(i)]['test_file'] = cwd + f"/data/{core}/test_list/{core}_depth1_{state}_tau/depth1_{i}.conf"
      test_list_config[str(i)]['logfile'] =  cwd + f"/data/{core}/log/{core}_depth1_{state}_tau/depth1_{i}.log"
   
   with open(f'./data/{core}/config/{core}_depth1_{state}_tau/test_list.conf', 'w') as testconfFile:
      test_list_config.write(testconfFile)

def gen_service_request_config(cases, core, state):
   cwd = os.path.dirname(os.path.realpath(__file__))
   test_list_dir = f'./data/{core}/test_list/{core}_depth1_{state}_sr'
   conf_dir = f'./data/{core}/config/{core}_depth1_{state}_sr'
   dir_list = [test_list_dir, conf_dir]
   for dir in dir_list:
      if not os.path.exists(dir):
            print(f"[os] makedir {dir}")
            os.makedirs(dir)

   test_list_config = configparser.ConfigParser()
   config_list = configparser.ConfigParser()
   config_list.read('./test_msg/test_list.conf', encoding='utf-8')
   for i in range(cases):
      config_list['lte']['name'] = cwd + f"/data/message/service_request/service_request_{i}.conf"
      with open(f'./data/{core}/test_list/{core}_depth1_{state}_sr/depth1_{i}.conf', 'w') as configfile:
         config_list.write(configfile)
      
      test_list_config[str(i)] = {}
      test_list_config[str(i)]['test_file'] = cwd + f"/data/{core}/test_list/{core}_depth1_{state}_sr/depth1_{i}.conf"
      test_list_config[str(i)]['logfile'] =  cwd + f"/data/{core}/log/{core}_depth1_{state}_sr/depth1_{i}.log"
   
   with open(f'./data/{core}/config/{core}_depth1_{state}_sr/test_list.conf', 'w') as testconfFile:
      test_list_config.write(testconfFile)

def gen_detach_request_config(cases, core, state):
   cwd = os.path.dirname(os.path.realpath(__file__))
   test_list_dir = f'./data/{core}/test_list/{core}_depth1_{state}_detach'
   conf_dir = f'./data/{core}/config/{core}_depth1_{state}_detach'
   dir_list = [test_list_dir, conf_dir]
   for dir in dir_list:
      if not os.path.exists(dir):
            print(f"[os] makedir {dir}")
            os.makedirs(dir)

   test_list_config = configparser.ConfigParser()
   config_list = configparser.ConfigParser()
   config_list.read('./test_msg/test_list.conf', encoding='utf-8')
   for i in range(cases):
      config_list['lte']['name'] = cwd + f"/data/message/detach_request/detach_request_{i}.conf"
      with open(f'./data/{core}/test_list/{core}_depth1_{state}_detach/depth1_{i}.conf', 'w') as configfile:
         config_list.write(configfile)
      
      test_list_config[str(i)] = {}
      test_list_config[str(i)]['test_file'] = cwd + f"/data/{core}/test_list/{core}_depth1_{state}_detach/depth1_{i}.conf"
      test_list_config[str(i)]['logfile'] =  cwd + f"/data/{core}/log/{core}_depth1_{state}_detach/depth1_{i}.log"
   
   with open(f'./data/{core}/config/{core}_depth1_{state}_detach/test_list.conf', 'w') as testconfFile:
      test_list_config.write(testconfFile)

def gen_attach_request_config(cases, core, state):
   cwd = os.path.dirname(os.path.realpath(__file__))
   test_list_dir = f'./data/{core}/test_list/{core}_depth1_{state}_attach'
   conf_dir = f'./data/{core}/config/{core}_depth1_{state}_attach'
   dir_list = [test_list_dir, conf_dir]
   for dir in dir_list:
      if not os.path.exists(dir):
            print(f"[os] makedir {dir}")
            os.makedirs(dir)

   test_list_config = configparser.ConfigParser()
   config_list = configparser.ConfigParser()
   config_list.read('./test_msg/test_list.conf', encoding='utf-8')
   for i in range(cases):
      config_list['lte']['name'] = cwd + f"/data/message/attach_request/attach_request_{i}.conf"
      with open(f'./data/{core}/test_list/{core}_depth1_{state}_attach/depth1_{i}.conf', 'w') as configfile:
         config_list.write(configfile)
      
      test_list_config[str(i)] = {}
      test_list_config[str(i)]['test_file'] = cwd + f"/data/{core}/test_list/{core}_depth1_{state}_attach/depth1_{i}.conf"
      test_list_config[str(i)]['logfile'] =  cwd + f"/data/{core}/log/{core}_depth1_{state}_attach/depth1_{i}.log"
   
   with open(f'./data/{core}/config/{core}_depth1_{state}_attach/test_list.conf', 'w') as testconfFile:
      test_list_config.write(testconfFile)

def split_conf_file(conf_file, lines_per_file, output_file_path_and_prefix):
   if not os.path.exists(conf_file):
      return
   
   with open(conf_file, 'r') as file:
      file_index = 0
      output_filename = f"{output_file_path_and_prefix}_{file_index}.conf"
      output_file = open(output_filename, 'w')

      for line_number, line in enumerate(file, start=1):
         output_file.write(line)
         if line_number % lines_per_file == 0:
            output_file.close()
            file_index += 1
            output_filename = f"{output_file_path_and_prefix}_{file_index}.conf"
            output_file = open(output_filename, 'w')
      output_file.close()

      if os.path.exists(conf_file):
         try:
            os.remove(conf_file)
            print(f"File '{conf_file}' has been deleted.")
         except Exception as e:
            print(f"An error occurred while trying to delete the file: {e}")  

if __name__ == "__main__":
  arg_parser = argparse.ArgumentParser()
  arg_parser.add_argument('-c', '--core', help='name of core network [amari, srsran, nextepc, open5gs]')
  arg_parser.add_argument('-s', '--state', help='type of testing state [DEREGI/CONN/IDLE]')
  args = arg_parser.parse_args()
  dir_list = [f'./data/message',f'./data/{args.core}', f'./data/{args.core}/log', f'./data/{args.core}/config', f'./data/{args.core}/test_list']
  for dir in dir_list:
      if not os.path.exists(dir):
         print(f"[os] makedir {dir}")
         os.makedirs(dir)

  attach_request_cases = gen_attach_request()
  print(f"# of attach request: {attach_request_cases}")
  gen_attach_request_config(attach_request_cases, args.core, args.state)
  
  detach_request_cases = gen_detach_request()
  gen_detach_request_config(detach_request_cases, args.core, args.state)
  print(f"# of detach request: {detach_request_cases}")
  
  service_request_cases = gen_service_request()
  print(f"# of service request: {service_request_cases}")
  gen_service_request_config(service_request_cases, args.core, args.state)
  
  tau_request_cases = gen_TAU_request()
  print(f"# of tau request: {tau_request_cases}")
  gen_tau_request_config(tau_request_cases, args.core, args.state)

  gen_attach_complete()
  gen_auth_failure()
  gen_auth_response()
  gen_identity_response()
  gen_security_mode_complete()
  gen_security_mode_reject()
