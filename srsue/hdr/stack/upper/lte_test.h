#ifndef SRSUE_LTE_TEST_H
#define SRSUE_LTE_TEST_H

#include <string>
#include <map>
#include <iterator>
#include <iostream>
#include <cstdio>
#include <cstring>
#include "nas_base.h"
#include "srsran/asn1/liblte_mme.h"
#include "srsran/common/buffer_pool.h"
#include "srsran/common/common.h"
#include "srsran/common/nas_pcap.h"
#include "srsran/common/security.h"
#include "srsran/common/stack_procedure.h"
#include "srsran/common/task_scheduler.h"
#include "srsran/interfaces/ue_nas_interfaces.h"
#include "srsran/srslog/srslog.h"
#include "srsue/hdr/stack/upper/nas_config.h"
#include "srsue/hdr/stack/upper/nas_emm_state.h"
#include "srsue/hdr/stack/upper/nas_metrics.h"
#include "srsue/hdr/stack/upper/nas_base.h"
#include "srsran/interfaces/ue_usim_interfaces.h"

extern std::ofstream log_stream; //open ofstream when initiating tmsg structure

using namespace srsran;

namespace srsue {

class usim_interface_nas;
class gw_interface_nas;
class rrc_interface_nas;
class nas_base;

struct custom_ctxt_t
{
    // From nas_sec_ctxt
    uint8_t                              ksi;
    uint8_t                              k_asme[32];
    uint32_t                             k_enb_count;
    LIBLTE_MME_EPS_MOBILE_ID_GUTI_STRUCT guti;

    // From nas_sec_base_ctxt
    uint8_t                             k_nas_enc[32] = {};
    uint8_t                             k_nas_int[32] = {};
    srsran::CIPHERING_ALGORITHM_ID_ENUM cipher_algo;
    srsran::INTEGRITY_ALGORITHM_ID_ENUM integ_algo;
    uint32_t                            tx_count;
    uint32_t                            rx_count;
};

struct attacker_usim_t
{
    uint8_t op[16] = {};
    uint8_t opc[16] = {};
    uint8_t k[16] = {};

    uint8_t amf[2]    = {};
    uint8_t mac[8]   = {};
    uint8_t autn[16] = {};

    uint8_t ck[16]             = {};
    uint8_t ik[16]             = {};
    uint8_t ak[6]             = {};
    uint8_t k_asme[32]        = {};
    uint8_t auts[14]     = {};
};

struct tfile_args_t
{
    std::string tfile_name;
    std::string current_tag;
    std::vector<std::string> test_tag;
    std::map<std::string, std::string> tmsg_file;
    std::map<std::string, std::string> result_file;

    int tfile_total = 0;
    int tfile_current = 0;
};


struct tmsg_args_t
{
    // tfile variable
    tfile_args_t tfile_args = {};

    std::string special_tag;  // specific tag value for one-time run

    std::string test_tag;
    std::string filename;
    std::vector<std::string> msg_list;
    int tmsg_cnt = 0;
    int current_cnt = 0;
    std::string current_file;
    std::map<std::string, std::string> conf_map;
    
    //For adding log file
    std::string logfile;
    // std::ofstream log_stream; //open ofstream when initiating tmsg structure 

    uint8_t sec_hdr;
    std::string mac_flag;

    // Origin ctxt
    custom_ctxt_t test_ctxt = {};
    attacker_usim_t attacker_usim = {};
    // srsue::nas_base::nas_sec_base_ctxt origin_ctxt_base = {};
    // srsue::nas_base::nas_sec_ctxt origin_ctxt = {};

    // authentication failure & response
    uint8_t auth_res[16] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    int auth_res_len = 0;
    uint8_t origin_res[16] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    uint8_t origin_k_asme[32];

    // identity response
    uint8 id_type = 0x1;

    // attach complete
    uint8 bearer_id = 0;
    uint8 transaction_id = 0;
    LIBLTE_MME_EPS_MOBILE_ID_GUTI_STRUCT origin_guti;

    // security mode complete & reject
    bool reject_flag = false;
    bool imeisv_present = false;
    uint8_t smc_reject_cause = 0x0;
};


class test
{
public:
    std::string default_result_file = "/tmp/nas.log";
    std::string msg_type;
    tmsg_args_t tmsg;
    // extern std::ofstream log_stream; //open ofstream when initiating tmsg structure 
    int  init(usim_interface_nas* usim_, rrc_interface_nas* rrc_, gw_interface_nas* gw_);

    int tmsg_reset();
    int parse_test_list(tmsg_args_t &tmsg);
    int parse_msg_list();
    void parse_msg_conf();
    int parse_test_security_algorithm_list(std::string algorithm_string, bool* algorithm_caps);
    int parse_hdr_and_mac();
    int set_mac_value(LIBLTE_BYTE_MSG_STRUCT* msg);

    int gen_test_attach_request(LIBLTE_MME_ATTACH_REQUEST_MSG_STRUCT &attach_req, srsue::nas_base::nas_sec_ctxt ctxt, bool have_guti, bool have_ctxt);
    int gen_test_pdn_connectivity_request(LIBLTE_MME_PDN_CONNECTIVITY_REQUEST_MSG_STRUCT &pdn_con_req);
    int gen_test_authentication_failure(LIBLTE_MME_AUTHENTICATION_FAILURE_MSG_STRUCT &auth_failure, const uint8_t *res);
    int gen_test_authentication_response(LIBLTE_MME_AUTHENTICATION_RESPONSE_MSG_STRUCT &auth_resp, const uint8_t *res, const size_t res_len);
    int gen_test_identity_response(LIBLTE_MME_ID_RESPONSE_MSG_STRUCT &id_resp, const uint8_t id_type, srsue::nas_base::nas_sec_ctxt ctxt);
    int gen_test_detach_request(LIBLTE_MME_DETACH_REQUEST_MSG_STRUCT &detach_req, srsue::nas_base::nas_sec_ctxt ctxt, bool have_guti, bool have_ctxt);
    int gen_test_attach_complete(LIBLTE_MME_ACTIVATE_DEFAULT_EPS_BEARER_CONTEXT_ACCEPT_MSG_STRUCT &esm_context);
    int gen_test_sec_mode_complete(LIBLTE_MME_SECURITY_MODE_COMPLETE_MSG_STRUCT &sec_mode_comp, srsue::nas_base::nas_sec_ctxt ctxt);
    int gen_test_sec_mode_reject(LIBLTE_MME_SECURITY_MODE_REJECT_MSG_STRUCT &sec_mode_rej);
    int gen_test_service_request(LIBLTE_MME_SERVICE_REQUEST_MSG_STRUCT &service_req, srsue::nas_base::nas_sec_ctxt ctxt, const uint32_t tx_count);
    int gen_test_tau_request(LIBLTE_MME_TRACKING_AREA_UPDATE_REQUEST_MSG_STRUCT &tau_req, srsue::nas_base::nas_sec_ctxt ctxt);

    bool check_test_num();

    auth_result_t attacker_generate_authentication_response(uint8_t* rand,
                                                     uint8_t* autn_enb,
                                                     uint16_t mcc,
                                                     uint16_t mnc,
                                                     uint8_t* res,
                                                     int*     res_len,
                                                     uint8_t* k_asme_);
    auth_result_t attacker_gen_auth_res_milenage(uint8_t* rand, uint8_t* autn_enb, uint8_t* res, int* res_len, uint8_t* ak_xor_sqn);


private:
    rrc_interface_nas*  rrc_test  = nullptr;
    usim_interface_nas* usim_test = nullptr;
    gw_interface_nas*   gw_test   = nullptr;

    std::ofstream ofs;

};


}
#endif // SRSUE_LTE_TEST_H