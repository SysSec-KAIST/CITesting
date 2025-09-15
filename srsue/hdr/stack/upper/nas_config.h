/**
 * Copyright 2013-2023 Software Radio Systems Limited
 *
 * This file is part of srsRAN.
 *
 * srsRAN is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of
 * the License, or (at your option) any later version.
 *
 * srsRAN is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * A copy of the GNU Affero General Public License can be found in
 * the LICENSE file in the top-level directory of this distribution
 * and at http://www.gnu.org/licenses/.
 *
 */

#ifndef SRSUE_NAS_CONFIG_H
#define SRSUE_NAS_CONFIG_H

#include "srsran/interfaces/ue_nas_interfaces.h"
#include <string>
#include "srsue/hdr/stack/upper/lte_test.h"

namespace srsue {

struct nas_sim_args_t {
  int airplane_t_on_ms  = -1;
  int airplane_t_off_ms = -1;
};

class nas_args_t
{
public:
  nas_args_t() : force_imsi_attach(false) {}
  ~nas_args_t() = default;
  std::string    apn_name;
  std::string    apn_protocol;
  std::string    apn_user;
  std::string    apn_pass;
  bool           force_imsi_attach;
  std::string    eia;
  std::string    eea;
  nas_sim_args_t sim;
  //<CITesting Flag>
  bool           emergency_attach;
  bool           sec_hdr_plain;
  int            auth_fail_cause;
  bool           attach_mac_zero;
  bool           attach_plain;
  bool           keep_attach;
  bool           default_pcap_loc;
  bool           verify_sr;
  tmsg_args_t tmsg;

  //Testing mode/role
  std::string testing_mode;
  std::string testing_role;
  std::string testing_state;
  int controller_port;
  
  //Testing IP
  std::string testing_ip;
  // 5G args
  std::string    ia5g;
  std::string    ea5g;
  std::vector<pdu_session_cfg_t> pdu_session_cfgs;
};

class nas_5g_args_t
{
public:
  nas_5g_args_t() : force_imsi_attach(false) {}
  ~nas_5g_args_t() = default;
  bool force_imsi_attach;

  // Need EPS sec capabilities in 5G
  std::string eia;
  std::string eea;

  // 5G Security capabilities
  std::string                    ia5g;
  std::string                    ea5g;
  std::vector<pdu_session_cfg_t> pdu_session_cfgs;
  // slicing configuration
  bool enable_slicing;
  int  nssai_sst;
  int  nssai_sd;
};

} // namespace srsue
#endif // SRSUE_NAS_COMMON_H
