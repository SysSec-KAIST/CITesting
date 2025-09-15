#include "srsran/common/bcd_helpers.h"
#include "srsran/common/security.h"
#include "srsran/common/string_helpers.h"
#include <fstream>
#include <iomanip>
#include <iostream>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <sys/mman.h>
#include <csignal>
#include <sstream>
#include <map>
#include <iterator>



#include "srsran/asn1/liblte_mme.h"
#include "srsran/common/standard_streams.h"
#include "srsran/interfaces/ue_gw_interfaces.h"
#include "srsran/interfaces/ue_rrc_interfaces.h"
#include "srsran/interfaces/ue_usim_interfaces.h"
#include "srsue/hdr/stack/upper/nas.h"
// #include "srsue/hdr/stack/upper/nas_idle_procedures.h"
#include "srsue/hdr/stack/upper/lte_test.h"
// #include "srsue/hdr/metrics_csv.h"
// #include "srsue/hdr/metrics_json.h"
// #include "srsue/hdr/metrics_stdout.h"
// #include "srsran/support/emergency_handlers.h"
// #include "srsran/support/signal_handler.h"
// #include "srsran/common/config_file.h"
#include "srsran/srsran.h"
#include "srsran/common/crash_handler.h"
#include "srsran/common/common_helper.h"
#include "srsran/srslog/srslog.h"
#include "srsue/hdr/stack/upper/nas_base.h"

std::ofstream log_stream; //Declare ofstream object

using namespace srsran;

namespace srsue {

int test::init(usim_interface_nas* usim_, rrc_interface_nas* rrc_, gw_interface_nas* gw_)
{
    usim_test = usim_;
    rrc_test  = rrc_;
    gw_test   = gw_;

    std::stringstream ss_k;
    ss_k << std::hex << std::setfill('0');
    for(int i=0; i<16; i++) ss_k << std::setw(2) << std::setfill('0') << (int)tmsg.attacker_usim.k[i];

    std::stringstream ss_opc;
    ss_opc << std::hex << std::setfill('0');
    for(int i=0; i<16; i++) ss_opc << std::setw(2) << std::setfill('0') << (int)tmsg.attacker_usim.opc[i];
    return 0;
}

int test::tmsg_reset()
{
    tmsg.current_cnt = 0;
    tmsg.tmsg_cnt = 0;
    tmsg.msg_list.clear();
    std::vector<std::string>(tmsg.msg_list).swap(tmsg.msg_list);
    tmsg.test_ctxt = {};
    return SRSRAN_SUCCESS;
}

int test::parse_test_list(tmsg_args_t &tmsg)
{
    srsran::console("---------------------------Start <%s>---------------------------\n", __func__);
    srsran::console("Reading Test List File: %s\n", tmsg.tfile_args.tfile_name.c_str());
    std::string line;
    std::ifstream file(tmsg.tfile_args.tfile_name);
    const char* list_key = "test_file";
    const char* result_key = "logfile";
    bool list_flag = true;
    bool result_flag = true;
    bool one_tag_find = false;

    if (tmsg.special_tag.compare("none") != 0)
    {
        srsran::console("Run only one tag (%s)\n", tmsg.special_tag.c_str());
        while (getline(file, line))
        {
            std::stringstream ss(line);
            std::string buf;
            if (line.substr(0,1).compare("[") != 0) continue;
            buf = line.substr(1, line.size()-2);
            if (buf.compare(tmsg.special_tag) != 0) continue;
            tmsg.tfile_args.test_tag.push_back(buf);
            tmsg.tfile_args.tfile_total++;

            getline(file, line);
            if (line.substr(0, strlen(list_key)).compare(list_key) != 0)
            {
                srsran::console("[error] test_file field error!\n");
                return SRSRAN_ERROR;
            }
            std::stringstream ss_1(line);
            while (getline(ss_1, buf, '=')){}
            buf.erase(remove(buf.begin(), buf.end(), ' '), buf.end());
            tmsg.tfile_args.tmsg_file[tmsg.tfile_args.test_tag.back()] = buf;
            log_stream.open(tmsg.logfile, std::ios_base::app);
            srsran::console("[debug] Test file: %s\n", buf.c_str());

            getline(file, line);
            if (line.substr(0, strlen(result_key)).compare(result_key) != 0)
            {
                srsran::console("[error] logfile field error!\n");
                return SRSRAN_ERROR;
            }
            std::stringstream ss_2(line);
            while (getline(ss_2, buf, '=')){}
            buf.erase(remove(buf.begin(), buf.end(), ' '), buf.end());
            tmsg.tfile_args.result_file[tmsg.tfile_args.test_tag.back()] = buf;
            srsran::console("[debug] Log file: %s\n", buf.c_str());
        }
    }
    else
    {
        while (getline(file, line))
        {
            if ((line.substr(0,1).compare("#") == 0) || (line.size() < 1))  continue;
            
            std::stringstream ss(line);
            std::string buf;
            if (line.substr(0,1).compare("[") == 0)
            {
                if (!list_flag)
                {
                    srsran::console("[error] There is no \"test_file\" value\n");
                    return SRSRAN_ERROR;
                }
                else if (!result_flag)
                {
                    srsran::console("[warning] There is no \"logfile\" value --> Use default value \"%s\"\n", default_result_file.c_str());
                    tmsg.tfile_args.result_file[tmsg.tfile_args.test_tag.back()] = default_result_file;
                }
                list_flag = false;
                result_flag = false;
                buf = line.substr(1, line.size()-2);
                tmsg.tfile_args.test_tag.push_back(buf);
                tmsg.tfile_args.tfile_total++;
            }
            else if (line.substr(0, strlen(list_key)).compare(list_key) == 0)
            {
                while (getline(ss, buf, '=')){}
                buf.erase(remove(buf.begin(), buf.end(), ' '), buf.end());
                tmsg.tfile_args.tmsg_file[tmsg.tfile_args.test_tag.back()] = buf;
                list_flag = true;
            }
            else if (line.substr(0, strlen(result_key)).compare(result_key) == 0)
            {
                while (getline(ss, buf, '=')){}
                buf.erase(remove(buf.begin(), buf.end(), ' '), buf.end());
                tmsg.tfile_args.result_file[tmsg.tfile_args.test_tag.back()] = buf;
                result_flag = true;
            }
            else
            {   
                srsran::console("[error] Invalid format\n");
                return SRSRAN_ERROR;
            }
        }

        if (!list_flag)
        {
            srsran::console("[error] There is no \"msg_list_file\" value\n");
            return SRSRAN_ERROR;
        }
        else if (!result_flag)
        {
            srsran::console("[warning] There is no \"logfile\" value --> Use default value \"%s\"\n", default_result_file.c_str());
            tmsg.tfile_args.result_file[tmsg.tfile_args.test_tag.back()] = default_result_file;
        }
    }

    srsran::console("Total Test Number: %d\n", tmsg.tfile_args.tfile_total);
    srsran::console("-----------------------------End <%s> -----------------------------\n", __func__);
    return SRSRAN_SUCCESS;
}

int test::parse_msg_list()
{
    tmsg_reset(); // reset tmsg structure
    if (tmsg.tfile_args.tfile_current >= tmsg.tfile_args.tfile_total)
    {
        srsran::console("[debug] Last nubmer\n");
        return SRSRAN_ERROR_OUT_OF_BOUNDS;
    }
    tmsg.tfile_args.current_tag = tmsg.tfile_args.test_tag[tmsg.tfile_args.tfile_current];
    tmsg.test_tag = tmsg.tfile_args.current_tag;
    tmsg.filename = tmsg.tfile_args.tmsg_file[tmsg.tfile_args.current_tag];
    tmsg.logfile = tmsg.tfile_args.result_file[tmsg.tfile_args.current_tag];
    tmsg.tfile_args.tfile_current++;

    srsran::console("---------------------------Start <%s>---------------------------\n", __func__);
    std::cout << "+----------------------------------------------------+" << std::endl;
    std::cout << "|  * Test Msg List Parsing * " << std::endl;
    std::cout << "|   > Input   : " <<  tmsg.filename << std::endl;
    std::cout << "|   > Output  : " <<  tmsg.logfile << std::endl;
    std::cout << "+----------------------------------------------------+" << std::endl;

    //write test case flie name due to S1AP logging
    std::string filename = tmsg.filename;
    std::ofstream outputFile("/tmp/testcase.txt");
    if (outputFile.is_open()){
        outputFile << filename << std::endl;
        outputFile.close();
        printf("Successfully write test case name in /tmp/testcase.txt\n");
    } else {
        printf("[Error] /tmp/testcase.txt can not open\n");
    }
    
    std::string line;
    std::ifstream file(tmsg.filename);
    const char* key = "name";
    size_t len = strlen(key);

    while (getline(file, line))
    {
        if ((line.substr(0,1).compare("#") == 0) || (line.substr(0,1).compare("[") == 0) || (line.size() < 3))  continue;
        if (line.substr(0, len).compare(key) != 0)
        {
            srsran::console("key error. \'%s\'\n", tmsg.filename.c_str());
            return SRSRAN_ERROR;
        }
        std::stringstream ss(line);
        std::string buf;
        while (getline(ss, buf, '=')){}
        buf.erase(remove(buf.begin(), buf.end(), ' '), buf.end());
        srsran::console("[debug] conf name: %s\n", buf.c_str());
        tmsg.msg_list.push_back(buf);
        tmsg.tmsg_cnt++;
    }
    srsran::console("Total test message count: %d\n", tmsg.tmsg_cnt);

    srsran::console("-----------------------------End <%s>-----------------------------\n", __func__);
    return SRSRAN_SUCCESS;
}

void test::parse_msg_conf() // Parse Information Element(IE) of test
{
    std::string conf_file = tmsg.msg_list[tmsg.current_cnt];

    srsran::console("Test File Name: %s\n", conf_file.c_str());

    std::string line;
    std::ifstream file(conf_file);

    tmsg.conf_map.clear();
    tmsg.current_file = conf_file;

    if (tmsg.current_file.compare("pass") == 0)
    {
        srsran::console("PASS!\n");
        tmsg.current_cnt++;
        return;
    }

    while (getline(file, line))
    {
        if ((line.substr(0,1).compare("#") == 0) || (line.substr(0,1).compare("[") == 0) || (line.size() < 3))  continue;
        std::stringstream ss(line);
        std::string buf;
        std::string key;
        getline(ss, key, '=');
        key.erase(remove(key.begin(), key.end(), ' '), key.end());
        while (getline(ss, buf, '=')){}
        buf.erase(remove(buf.begin(), buf.end(), ' '), buf.end());
        tmsg.conf_map[key] = buf;
        std::cout << "-->  " << key << " = " << buf << std::endl;
    }
    if (parse_hdr_and_mac() != SRSRAN_SUCCESS) {
        srsran::console("ParseError!!\n");
    }
}

int test::parse_test_security_algorithm_list(std::string algorithm_string, bool* algorithm_caps)
{
  // parse and sanity check security algorithm list
  std::vector<uint8_t> cap_list;
  srsran::string_parse_list(algorithm_string, ',', cap_list);
  if (cap_list.empty()) {
    srsran::console("Empty security list. Select at least one security algorithm.");
    return SRSRAN_ERROR;
  }
  for (std::vector<uint8_t>::const_iterator it = cap_list.begin(); it != cap_list.end(); ++it) {
    if (*it < 8) {
      algorithm_caps[*it] = true;
    } else {
      srsran::console("EEA/EIA/5G-EA/5G-IA %d is not a valid algorithm.", *it);
      return SRSRAN_ERROR;
    }
  }
  return SRSRAN_SUCCESS;
}

int test::parse_hdr_and_mac()
{
    std::string conf_field;
    std::string find_key;

    // mac_value
    find_key = "mac_value";
    if (!tmsg.conf_map.count(find_key)) {
        srsran::console("\"%s\" is missing in \"%s\" file\n", find_key.c_str(), tmsg.current_file.c_str());
        return SRSRAN_ERROR;
    }
    tmsg.mac_flag = tmsg.conf_map[find_key];
    srsran::console("MAC value: %s\n", tmsg.mac_flag.c_str());

    // security_header_type
    find_key = "security_header_type";
    if (!tmsg.conf_map.count(find_key)) {
        srsran::console("\"%s\" is missing in \"%s\" file\n", find_key.c_str(), tmsg.current_file.c_str());
        return SRSRAN_ERROR;
    }
    conf_field = tmsg.conf_map[find_key];
    srsran::console("Security Header Type: %s\n", conf_field.c_str());
    if (conf_field.compare("plain") == 0) {
        tmsg.sec_hdr = LIBLTE_MME_SECURITY_HDR_TYPE_PLAIN_NAS;
    }
    else if (conf_field.compare("integrity") == 0) {
        tmsg.sec_hdr = LIBLTE_MME_SECURITY_HDR_TYPE_INTEGRITY;
    }
    else if (conf_field.compare("integrity_and_cipher") == 0) {
        tmsg.sec_hdr = LIBLTE_MME_SECURITY_HDR_TYPE_INTEGRITY_AND_CIPHERED;
    }
    else if (conf_field.compare("integrity_w_new") == 0) {
        tmsg.sec_hdr = LIBLTE_MME_SECURITY_HDR_TYPE_INTEGRITY_WITH_NEW_EPS_SECURITY_CONTEXT;
    }
    else if (conf_field.compare("integrity_and_cipher_w_new") == 0) {
        tmsg.sec_hdr = LIBLTE_MME_SECURITY_HDR_TYPE_INTEGRITY_AND_CIPHERED_WITH_NEW_EPS_SECURITY_CONTEXT;
    }
    else if (conf_field.compare("integrity_and_partial_cipher") == 0) {
        tmsg.sec_hdr = 0x5;
    }
    else if (conf_field.compare("service_req_header") == 0) {
        tmsg.sec_hdr = LIBLTE_MME_SECURITY_HDR_TYPE_SERVICE_REQUEST;
    }
    else if (conf_field.compare("reserved") == 0) {
        tmsg.sec_hdr = 0x6;
    }
    else if (conf_field.compare("unused") == 0) {
        tmsg.sec_hdr = 0xF;
    }
    else {
        return SRSRAN_ERROR;
    }
    return SRSRAN_SUCCESS;
}

int test::set_mac_value(LIBLTE_BYTE_MSG_STRUCT* msg)
{
    srsran::console("<%s>\n", __func__);
    srsran::console("mac_value: %s\n", tmsg.mac_flag.c_str());
    if (tmsg.sec_hdr >= LIBLTE_MME_SECURITY_HDR_TYPE_INTEGRITY) {
        if (tmsg.mac_flag.compare("invalid") == 0) {
            msg->msg[1] = 0x12;
            msg->msg[2] = 0x34;
            msg->msg[3] = 0x56;
            msg->msg[4] = 0x78;
        }
        else if (tmsg.mac_flag.compare("zero") == 0) {
            msg->msg[1] = 0x00;
            msg->msg[2] = 0x00;
            msg->msg[3] = 0x00;
            msg->msg[4] = 0x00; 
        }
        else if (tmsg.mac_flag.compare("ff") == 0) {
            msg->msg[1] = 0xff;
            msg->msg[2] = 0xff;
            msg->msg[3] = 0xff;
            msg->msg[4] = 0xff;
        }
        else {
            srsran::console("Using original MAC value\n");
        }
    }
    return SRSRAN_SUCCESS;
}


int test::gen_test_attach_request(LIBLTE_MME_ATTACH_REQUEST_MSG_STRUCT &attach_req, srsue::nas_base::nas_sec_ctxt ctxt, bool have_guti, bool have_ctxt)
{
    srsran::console("<%s> log stream open---------------------------\n", __func__);
    srsran::console("---------------------------Start <%s> ---------------------------\n", __func__);
    srsran::console("Test Message Number: %d\n", tmsg.current_cnt+1);

    tmsg.current_cnt++;
    std::string conf_field;
    std::string find_key;
    
    srsran::console("Test File Name: %s\n", tmsg.current_file.c_str());
    srsran::console("Log File Name: %s\n", tmsg.logfile.c_str());
 
    log_stream << "\n---------- Test Configuration ----------" << std::endl;
    log_stream << tmsg.current_file.c_str() << std::endl;
    log_stream << "Message Type: " << tmsg.conf_map["msg_type"].c_str() << std::endl;

    //For logging MAC and Security Header Type
    find_key = "mac_value";
    if (!tmsg.conf_map.count(find_key)) {
        srsran::console("\"%s\" is missing in \"%s\" file\n", find_key.c_str(), tmsg.current_file.c_str());
        return SRSRAN_ERROR;
    }
    tmsg.mac_flag = tmsg.conf_map[find_key];
    log_stream << "MAC Value: " << tmsg.mac_flag.c_str() << std::endl;

    // security_header_type
    find_key = "security_header_type";
    if (!tmsg.conf_map.count(find_key)) {
        srsran::console("\"%s\" is missing in \"%s\" file\n", find_key.c_str(), tmsg.current_file.c_str());
        return SRSRAN_ERROR;
    }
    conf_field = tmsg.conf_map[find_key];
    log_stream << "Security Header Type: " << conf_field.c_str() << std::endl;

    find_key = "sqn";
    if (!tmsg.conf_map.count(find_key)) {
        srsran::console("\"%s\" is missing in \"%s\" file\n", find_key.c_str(), tmsg.current_file.c_str());
        return SRSRAN_ERROR;
    }
    conf_field = tmsg.conf_map[find_key];
    log_stream << "sqn: " << conf_field.c_str() << std::endl;

    if (tmsg.conf_map["msg_type"].compare("attach_request") != 0)
    {
        srsran::console("Error:: msg_type mismatch with (attach_request)\n");
        tmsg.current_cnt--;
        return SRSRAN_ERROR;
    }

    // attach_type
    find_key = "attach_type";
    if (!tmsg.conf_map.count(find_key)) {
        srsran::console("\"%s\" is missing in \"%s\" file\n", find_key.c_str(), tmsg.current_file.c_str());
        return SRSRAN_ERROR;
    }
    conf_field = tmsg.conf_map[find_key];
    srsran::console("Attach Type: %s\n", conf_field.c_str());
    //For logging configuration
    log_stream << "Attach Type: " << conf_field.c_str() << std::endl;

    if (conf_field.compare("combined") == 0) {
        attach_req.eps_attach_type = LIBLTE_MME_EPS_ATTACH_TYPE_EPS_ATTACH;
    }
    else if (conf_field.compare("emergency") == 0) {
        attach_req.eps_attach_type = LIBLTE_MME_EPS_ATTACH_TYPE_EPS_EMERGENCY_ATTACH;
    }
    else {
        return SRSRAN_ERROR;
    }


    // mobile_identity
    find_key = "mobile_identity";
    if (!tmsg.conf_map.count(find_key)) {
        srsran::console("\"%s\" is missing in \"%s\" file\n", find_key.c_str(), tmsg.current_file.c_str());
        return SRSRAN_ERROR;
    }
    conf_field = tmsg.conf_map[find_key];
    log_stream << "Mobile Identity: " << conf_field.c_str() << std::endl;

    attach_req.tmsi_status_present      = false;
    attach_req.old_guti_type_present    = false;
    srsran::console("Mobile Identity: %s\n", conf_field.c_str());
    if (conf_field.compare("imsi_v") == 0) {
        attach_req.eps_mobile_id.type_of_id = LIBLTE_MME_EPS_MOBILE_ID_TYPE_IMSI;
        usim_test->get_imsi_vec(attach_req.eps_mobile_id.imsi, 15);
        srsran::console("IMSI_v: %s\n", usim_test->get_imsi_str().c_str());
    }
    else if (conf_field.compare("guti_v") == 0) {
        if (have_guti && have_ctxt) {
            attach_req.tmsi_status_present      = true;
            attach_req.tmsi_status              = LIBLTE_MME_TMSI_STATUS_VALID_TMSI;
            attach_req.eps_mobile_id.type_of_id = LIBLTE_MME_EPS_MOBILE_ID_TYPE_GUTI;
            memcpy(&attach_req.eps_mobile_id.guti, &ctxt.guti, sizeof(LIBLTE_MME_EPS_MOBILE_ID_GUTI_STRUCT));
            attach_req.old_guti_type         = LIBLTE_MME_GUTI_TYPE_NATIVE;
            attach_req.old_guti_type_present = true;
        }
        else {
            srsran::console("ERROR There is no ctxt\n");
            return SRSRAN_ERROR;
        }
        srsran::console("GUTI_v: %x\n", ctxt.guti.m_tmsi);
    }
    else {
        return SRSRAN_ERROR;
    }

    // tsc_flag
    find_key = "tsc_flag";
    if (!tmsg.conf_map.count(find_key)) {
        srsran::console("\"%s\" is missing in \"%s\" file\n", find_key.c_str(), tmsg.current_file.c_str());
        return SRSRAN_ERROR;
    }
    conf_field = tmsg.conf_map[find_key];
    log_stream << "TSC Flag: " << conf_field.c_str() << std::endl;

    srsran::console("TSC Flag: %s\n", conf_field.c_str());
    if (conf_field.compare("native") == 0) {
        attach_req.nas_ksi.tsc_flag = LIBLTE_MME_TYPE_OF_SECURITY_CONTEXT_FLAG_NATIVE;
    }
    else if (conf_field.compare("mapped") == 0) {
        attach_req.nas_ksi.tsc_flag = LIBLTE_MME_TYPE_OF_SECURITY_CONTEXT_FLAG_MAPPED;
    }
    else {
        return SRSRAN_ERROR;
    }

    // ksi
    find_key = "ksi";
    if (!tmsg.conf_map.count(find_key)) {
        srsran::console("\"%s\" is missing in \"%s\" file\n", find_key.c_str(), tmsg.current_file.c_str());
        return SRSRAN_ERROR;
    }
    conf_field = tmsg.conf_map[find_key];
    log_stream << "KSI: " << conf_field.c_str() << std::endl;

    srsran::console("KSI: %s\n", conf_field.c_str());
    if (conf_field.compare("7") == 0) {
        attach_req.nas_ksi.nas_ksi = 7;
    }
    else if (conf_field.compare("valid") == 0) {
        if (have_guti && have_ctxt) {
            attach_req.nas_ksi.nas_ksi = ctxt.ksi;
        }
        else {
            attach_req.nas_ksi.nas_ksi = 3;
        }
    }
    else if (conf_field.compare("invalid") == 0) {
        if (have_guti && have_ctxt) {
            attach_req.nas_ksi.nas_ksi = (ctxt.ksi+1)%7;
        }
        else {
            attach_req.nas_ksi.nas_ksi = 3;
        }
    }
    else {
        return SRSRAN_ERROR;
    }

    // security capability
    find_key = "eea";
    if (!tmsg.conf_map.count(find_key)) {
        srsran::console("\"%s\" is missing in \"%s\" file\n", find_key.c_str(), tmsg.current_file.c_str());
        return SRSRAN_ERROR;
    }
    conf_field = tmsg.conf_map[find_key];
    log_stream << "EEA: " << conf_field.c_str() << std::endl;

    srsran::console("EEA: %s\n", conf_field.c_str());
    bool tmp_eea_caps[8] = {};
    if (parse_test_security_algorithm_list(conf_field, tmp_eea_caps) != SRSRAN_SUCCESS) {
        srsran::console("EEA parsing fail\n");
        return SRSRAN_ERROR;
    }
    find_key = "eia";
    if (!tmsg.conf_map.count(find_key)) {
        srsran::console("\"%s\" is missing in \"%s\" file\n", find_key.c_str(), tmsg.current_file.c_str());
        return SRSRAN_ERROR;
    }
    conf_field = tmsg.conf_map[find_key];
    log_stream << "EIA: " << conf_field.c_str() << std::endl;

    srsran::console("EIA: %s\n", conf_field.c_str());
    bool tmp_eia_caps[8] = {};
    if (parse_test_security_algorithm_list(conf_field, tmp_eia_caps) != SRSRAN_SUCCESS) {
        srsran::console("EIA parsing fail\n");
        return SRSRAN_ERROR;
    }

    for (u_int32_t i = 0; i < 8; i++) {
        attach_req.ue_network_cap.eea[i] = tmp_eea_caps[i];
        attach_req.ue_network_cap.eia[i] = tmp_eia_caps[i];
    }

    log_stream << "----------------------------------------\n" << std::endl;
    ofs.close();

    srsran::console("-----------------------------End <%s>-----------------------------\n", __func__);

    return SRSRAN_SUCCESS;
}

int test::gen_test_pdn_connectivity_request(LIBLTE_MME_PDN_CONNECTIVITY_REQUEST_MSG_STRUCT &pdn_con_req)
{
    if (tmsg.conf_map["msg_type"].compare("attach_request") != 0) {
        srsran::console("<%s> ERROR: test msg is not \'attach request\'\n", __func__);
        return SRSRAN_ERROR;
    }

    std::string conf_field;
    std::string find_key;
    std::string conf_attach_type;
    // esm_request_type
    find_key = "esm_request_type";
    if (!tmsg.conf_map.count(find_key)) {
        srsran::console("\"%s\" is missing in \"%s\" file\n", find_key.c_str(), tmsg.current_file.c_str());
        return SRSRAN_ERROR;
    }
    conf_field = tmsg.conf_map[find_key];
    conf_attach_type = tmsg.conf_map["attach_type"];

    if (conf_attach_type.compare("eps") == 0) {
        pdn_con_req.request_type = LIBLTE_MME_REQUEST_TYPE_INITIAL_REQUEST;
    }
    else if (conf_attach_type.compare("combined") == 0) {
        pdn_con_req.request_type = LIBLTE_MME_REQUEST_TYPE_INITIAL_REQUEST;
    }
    else if (conf_attach_type.compare("emergency") == 0) {
        pdn_con_req.request_type = LIBLTE_MME_REQUEST_TYPE_EMERGENCY;
    }
    else if (conf_attach_type.compare("reserved") == 0) {
        pdn_con_req.request_type = LIBLTE_MME_REQUEST_TYPE_INITIAL_REQUEST;
    }
    else {
        return SRSRAN_ERROR;
    }

    return SRSRAN_SUCCESS;
}

int test::gen_test_authentication_failure(LIBLTE_MME_AUTHENTICATION_FAILURE_MSG_STRUCT &auth_failure, const uint8_t *res)
{
    srsran::console("---------------------------Start <%s>---------------------------\n", __func__);
    srsran::console("Test Message Number: %d\n", tmsg.current_cnt+1);
    tmsg.current_cnt++;

    srsran::console("Test File Name: %s\n", tmsg.current_file.c_str());

    std::string conf_field;
    std::string find_key;
    
    log_stream << "\n---------- Test Configuration ----------" << std::endl;
    log_stream << tmsg.current_file.c_str() << std::endl;
    log_stream << "Message Type: " << tmsg.conf_map["msg_type"].c_str() << std::endl;

    //For logging MAC and Security Header Type
    find_key = "mac_value";
    if (!tmsg.conf_map.count(find_key)) {
        srsran::console("\"%s\" is missing in \"%s\" file\n", find_key.c_str(), tmsg.current_file.c_str());
        return SRSRAN_ERROR;
    }
    tmsg.mac_flag = tmsg.conf_map[find_key];
    log_stream << "MAC Value: " << tmsg.mac_flag.c_str() << std::endl;

    // security_header_type
    find_key = "security_header_type";
    if (!tmsg.conf_map.count(find_key)) {
        srsran::console("\"%s\" is missing in \"%s\" file\n", find_key.c_str(), tmsg.current_file.c_str());
        return SRSRAN_ERROR;
    }
    conf_field = tmsg.conf_map[find_key];
    log_stream << "Security Header Type: " << conf_field.c_str() << std::endl;

    if (tmsg.conf_map["msg_type"].compare("authentication_failure") != 0)
    {
        srsran::console("Error:: msg_type mismatch with (authentication_failure)\n");
        tmsg.current_cnt--;
        return SRSRAN_ERROR;
    }

    find_key = "sqn";
    if (!tmsg.conf_map.count(find_key)) {
        srsran::console("\"%s\" is missing in \"%s\" file\n", find_key.c_str(), tmsg.current_file.c_str());
        return SRSRAN_ERROR;
    }
    conf_field = tmsg.conf_map[find_key];
    log_stream << "sqn: " << conf_field.c_str() << std::endl;

    // emm_cause
    find_key = "emm_cause";
    if (!tmsg.conf_map.count(find_key)) {
        srsran::console("\"%s\" is missing in \"%s\" file\n", find_key.c_str(), tmsg.current_file.c_str());
        return SRSRAN_ERROR;
    }
    conf_field = tmsg.conf_map[find_key];
    srsran::console("EMM Cause: %s\n", conf_field.c_str());
    log_stream << "EMM Cause: " << conf_field.c_str() << std::endl;
    if (conf_field.compare("mac_fail") == 0) {
        auth_failure.emm_cause = LIBLTE_MME_EMM_CAUSE_MAC_FAILURE;
    }
    else if (conf_field.compare("synch_fail") == 0) {
        auth_failure.emm_cause = LIBLTE_MME_EMM_CAUSE_SYNCH_FAILURE;
    }
    else if (conf_field.compare("unacceptable") == 0) {
        auth_failure.emm_cause = LIBLTE_MME_EMM_CAUSE_NON_EPS_AUTHENTICATION_UNACCEPTABLE;
    }
    else {
        return SRSRAN_ERROR;
    }

    // auth_fail_param
    find_key = "auth_fail_param";
    if (!tmsg.conf_map.count(find_key)) {
        srsran::console("\"%s\" is missing in \"%s\" file\n", find_key.c_str(), tmsg.current_file.c_str());
        return SRSRAN_ERROR;
    }
    conf_field = tmsg.conf_map[find_key];
    srsran::console("Authentication Failure Parameter: %s\n", conf_field.c_str());
    log_stream << "Auth Failure Parameter: " << conf_field.c_str() << std::endl;
    if (conf_field.compare("no_present") == 0) {
        auth_failure.auth_fail_param_present = false;
    }
    else if (conf_field.compare("valid") == 0) {
        auth_failure.auth_fail_param_present = true;
        memcpy(auth_failure.auth_fail_param, res, 14);
    }
    else if (conf_field.compare("invalid") == 0) {
        auth_failure.auth_fail_param_present = true;
        uint8_t tmp_res[16] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
        memcpy(auth_failure.auth_fail_param, tmp_res, 14);
    }
    else {
        return SRSRAN_ERROR;
    }

    log_stream << "----------------------------------------\n" << std::endl;
    ofs.close();

    srsran::console("---------------------------End <%s>-----------------------------\n", __func__);
    return SRSRAN_SUCCESS;
}

int test::gen_test_authentication_response(LIBLTE_MME_AUTHENTICATION_RESPONSE_MSG_STRUCT &auth_resp, const uint8_t *res, const size_t res_len)
{
    srsran::console("---------------------------Start <%s> ---------------------------\n", __func__);
    srsran::console("Test Message Number: %d\n", tmsg.current_cnt+1);

    tmsg.current_cnt++;

    srsran::console("Test File Name: %s\n", tmsg.current_file.c_str());

    
    std::string conf_field;
    std::string find_key;

    log_stream << "\n---------- Test Configuration ----------" << std::endl;
    log_stream << tmsg.current_file.c_str() << std::endl;
    log_stream << "Message Type: " << tmsg.conf_map["msg_type"].c_str() << std::endl;

    //For logging MAC and Security Header Type
    find_key = "mac_value";
    if (!tmsg.conf_map.count(find_key)) {
        srsran::console("\"%s\" is missing in \"%s\" file\n", find_key.c_str(), tmsg.current_file.c_str());
        return SRSRAN_ERROR;
    }
    tmsg.mac_flag = tmsg.conf_map[find_key];
    log_stream << "MAC Value: " << tmsg.mac_flag.c_str() << std::endl;

    // security_header_type
    find_key = "security_header_type";
    if (!tmsg.conf_map.count(find_key)) {
        srsran::console("\"%s\" is missing in \"%s\" file\n", find_key.c_str(), tmsg.current_file.c_str());
        return SRSRAN_ERROR;
    }
    conf_field = tmsg.conf_map[find_key];
    log_stream << "Security Header Type: " << conf_field.c_str() << std::endl;

    if (tmsg.conf_map["msg_type"].compare("authentication_response") != 0)
    {
        srsran::console("Error:: msg_type mismatch with (authentication_response)\n");
        tmsg.current_cnt--;
        return SRSRAN_ERROR;
    }

    // auth_resp_param
    find_key = "auth_resp_param";
    if (!tmsg.conf_map.count(find_key)) {
        srsran::console("\"%s\" is missing in \"%s\" file\n", find_key.c_str(), tmsg.current_file.c_str());
        return SRSRAN_ERROR;
    }
    conf_field = tmsg.conf_map[find_key];
    log_stream << "Auth Response Parameter: " << conf_field.c_str() << std::endl;
    srsran::console("Authentication Response Parameter: %s\n", conf_field.c_str());
    if (conf_field.compare("valid") == 0) {
        std::cout << "[Auth make] RES: " << std::hex << +tmsg.origin_res[0] << +tmsg.origin_res[1] << +tmsg.origin_res[2] << +tmsg.origin_res[3] << +tmsg.origin_res[4] << +tmsg.origin_res[5] << +tmsg.origin_res[6] << +tmsg.origin_res[7] << std::endl;
        memcpy(auth_resp.res, tmsg.origin_res, 8);
        auth_resp.res_len = 8;
    }
    else if (conf_field.compare("invalid") == 0) {
        uint8_t tmp_res[16] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
        memcpy(auth_resp.res, tmp_res, res_len);
    }
    else {
        return SRSRAN_ERROR;
    }

    log_stream << "----------------------------------------\n" << std::endl;
    ofs.close();
    
    srsran::console("---------------------------End <%s>-----------------------------\n", __func__);
    return SRSRAN_SUCCESS;
}

int test::gen_test_identity_response(LIBLTE_MME_ID_RESPONSE_MSG_STRUCT &id_resp, const uint8_t id_type, srsue::nas_base::nas_sec_ctxt ctxt)
{
    srsran::console("---------------------------Start <%s> ---------------------------\n", __func__);
    srsran::console("Test Message Number: %d\n", tmsg.current_cnt+1);

    tmsg.current_cnt++;

    srsran::console("Test File Name: %s\n", tmsg.current_file.c_str());
    
    std::string conf_field;
    std::string find_key;

    log_stream << "\n---------- Test Configuration ----------" << std::endl;
    log_stream << tmsg.current_file.c_str() << std::endl;
    log_stream << "Message Type: " << tmsg.conf_map["msg_type"].c_str() << std::endl;

    //For logging MAC and Security Header Type
    find_key = "mac_value";
    if (!tmsg.conf_map.count(find_key)) {
        srsran::console("\"%s\" is missing in \"%s\" file\n", find_key.c_str(), tmsg.current_file.c_str());
        return SRSRAN_ERROR;
    }
    tmsg.mac_flag = tmsg.conf_map[find_key];
    log_stream << "MAC Value: " << tmsg.mac_flag.c_str() << std::endl;

    // security_header_type
    find_key = "security_header_type";
    if (!tmsg.conf_map.count(find_key)) {
        srsran::console("\"%s\" is missing in \"%s\" file\n", find_key.c_str(), tmsg.current_file.c_str());
        return SRSRAN_ERROR;
    }
    conf_field = tmsg.conf_map[find_key];
    log_stream << "Security Header Type: " << conf_field.c_str() << std::endl;

    if (tmsg.conf_map["msg_type"].compare("identity_response") != 0)
    {
        srsran::console("Error:: msg_type mismatch with (identity_response)\n");
        tmsg.current_cnt--;
        return SRSRAN_ERROR;
    }

    find_key = "sqn";
    if (!tmsg.conf_map.count(find_key)) {
        srsran::console("\"%s\" is missing in \"%s\" file\n", find_key.c_str(), tmsg.current_file.c_str());
        return SRSRAN_ERROR;
    }
    conf_field = tmsg.conf_map[find_key];
    log_stream << "sqn: " << conf_field.c_str() << std::endl;

    // mobile_identity
    find_key = "mobile_identity";
    if (!tmsg.conf_map.count(find_key)) {
        srsran::console("\"%s\" is missing in \"%s\" file\n", find_key.c_str(), tmsg.current_file.c_str());
        return SRSRAN_ERROR;
    }
    conf_field = tmsg.conf_map[find_key];

    srsran::console("Mobile Identity: %s\n", conf_field.c_str());
    log_stream << "Mobile Identity: " << conf_field.c_str() << std::endl;
    if (conf_field.compare("imsi_v") == 0) {
        id_resp.mobile_id.type_of_id = LIBLTE_MME_MOBILE_ID_TYPE_IMSI;
        usim_test->get_imsi_vec(id_resp.mobile_id.imsi, 15);
        srsran::console("IMSI_v: %s\n", usim_test->get_imsi_str().c_str());
    }
    else if (conf_field.compare("imei_v") == 0) {
        id_resp.mobile_id.type_of_id = LIBLTE_MME_MOBILE_ID_TYPE_IMEI;
        usim_test->get_imei_vec(id_resp.mobile_id.imei, 15);
        srsran::console("IMEI_v: %s\n", usim_test->get_imei_str().c_str());
    }
    else if (conf_field.compare("imeisv_v") == 0) {
        id_resp.mobile_id.type_of_id = LIBLTE_MME_MOBILE_ID_TYPE_IMEISV;
        usim_test->get_imei_vec(id_resp.mobile_id.imeisv, 15);
        id_resp.mobile_id.imeisv[14] = 0;
        id_resp.mobile_id.imeisv[15] = 1;
        srsran::console("IMEISV_a: %s01\n", usim_test->get_imei_str().c_str());
    }
    else if (conf_field.compare("tmsi_v") == 0) {
        id_resp.mobile_id.type_of_id = LIBLTE_MME_MOBILE_ID_TYPE_TMSI;
        id_resp.mobile_id.tmsi = ctxt.guti.m_tmsi;
        srsran::console("TMSI_v: %x\n", ctxt.guti.m_tmsi);
    }
    else {
        return SRSRAN_ERROR;
    }


    log_stream << "----------------------------------------\n" << std::endl;
    ofs.close();

    srsran::console("---------------------------End <%s>-----------------------------\n", __func__);
    return SRSRAN_SUCCESS;
}

int test::gen_test_detach_request(LIBLTE_MME_DETACH_REQUEST_MSG_STRUCT &detach_req, srsue::nas_base::nas_sec_ctxt ctxt, bool have_guti, bool have_ctxt)
{
    srsran::console("---------------------------Start <%s> ---------------------------\n", __func__);
    srsran::console("Test Message Number: %d\n", tmsg.current_cnt+1);

    tmsg.current_cnt++;

    srsran::console("Test File Name: %s\n", tmsg.current_file.c_str());

    std::string conf_field;
    std::string find_key;

    log_stream << "\n---------- Test Configuration ----------" << std::endl;
    log_stream << tmsg.current_file.c_str() << std::endl;
    log_stream << "Message Type: " << tmsg.conf_map["msg_type"].c_str() << std::endl;

    //For logging MAC and Security Header Type
    find_key = "mac_value";
    if (!tmsg.conf_map.count(find_key)) {
        srsran::console("\"%s\" is missing in \"%s\" file\n", find_key.c_str(), tmsg.current_file.c_str());
        return SRSRAN_ERROR;
    }
    tmsg.mac_flag = tmsg.conf_map[find_key];
    log_stream << "MAC Value: " << tmsg.mac_flag.c_str() << std::endl;

    // security_header_type
    find_key = "security_header_type";
    if (!tmsg.conf_map.count(find_key)) {
        srsran::console("\"%s\" is missing in \"%s\" file\n", find_key.c_str(), tmsg.current_file.c_str());
        return SRSRAN_ERROR;
    }
    conf_field = tmsg.conf_map[find_key];
    log_stream << "Security Header Type: " << conf_field.c_str() << std::endl;

    if (tmsg.conf_map["msg_type"].compare("detach_request") != 0)
    {
        srsran::console("Error:: msg_type mismatch with (detach_request)\n");
        tmsg.current_cnt--;
        return SRSRAN_ERROR;
    }

    find_key = "sqn";
    if (!tmsg.conf_map.count(find_key)) {
        srsran::console("\"%s\" is missing in \"%s\" file\n", find_key.c_str(), tmsg.current_file.c_str());
        return SRSRAN_ERROR;
    }
    conf_field = tmsg.conf_map[find_key];
    log_stream << "sqn: " << conf_field.c_str() << std::endl;

    // detach_type
    find_key = "detach_type";
    if (!tmsg.conf_map.count(find_key)) {
        srsran::console("\"%s\" is missing in \"%s\" file\n", find_key.c_str(), tmsg.current_file.c_str());
        return SRSRAN_ERROR;
    }
    conf_field = tmsg.conf_map[find_key];
    srsran::console("Detach Type: %s\n", conf_field.c_str());
    //For logging configuration
    log_stream << "Detach Type: " << conf_field.c_str() << std::endl;

    if (conf_field.compare("imsi") == 0) {
        detach_req.detach_type.type_of_detach = LIBLTE_MME_TOD_UL_IMSI_DETACH;
    }
    else if (conf_field.compare("combined") == 0) {
        detach_req.detach_type.type_of_detach = LIBLTE_MME_TOD_UL_COMBINED_DETACH;
    }
    else {
        return SRSRAN_ERROR;
    }

    // switch_off
    find_key = "switch_off";
    if (!tmsg.conf_map.count(find_key)) {
        srsran::console("\"%s\" is missing in \"%s\" file\n", find_key.c_str(), tmsg.current_file.c_str());
        return SRSRAN_ERROR;
    }
    conf_field = tmsg.conf_map[find_key];
    srsran::console("Switch Off: %s\n", conf_field.c_str());
    //For logging configuration
    log_stream << "Switch Off: " << conf_field.c_str() << std::endl;

    if (conf_field.compare("normal_detach") == 0) {
        detach_req.detach_type.switch_off = 0;
    }
    else if (conf_field.compare("switch_off") == 0) {
        detach_req.detach_type.switch_off = 1;
    }
    else {
        return SRSRAN_ERROR;
    }

    // mobile_identity
    find_key = "mobile_identity";
    if (!tmsg.conf_map.count(find_key)) {
        srsran::console("\"%s\" is missing in \"%s\" file\n", find_key.c_str(), tmsg.current_file.c_str());
        return SRSRAN_ERROR;
    }
    conf_field = tmsg.conf_map[find_key];
    log_stream << "Mobile Identity: " << conf_field.c_str() << std::endl;

    srsran::console("Mobile Identity: %s\n", conf_field.c_str());
    if (conf_field.compare("imsi_v") == 0) {
        detach_req.eps_mobile_id.type_of_id = LIBLTE_MME_EPS_MOBILE_ID_TYPE_IMSI;
        usim_test->get_imsi_vec(detach_req.eps_mobile_id.imsi, 15);
        srsran::console("IMSI_v: %s\n", usim_test->get_imsi_str().c_str());
    }
    else if (conf_field.compare("guti_v") == 0) {
        if (have_guti && have_ctxt) {
            detach_req.eps_mobile_id.type_of_id = LIBLTE_MME_EPS_MOBILE_ID_TYPE_GUTI;
            memcpy(&detach_req.eps_mobile_id.guti, &ctxt.guti, sizeof(LIBLTE_MME_EPS_MOBILE_ID_GUTI_STRUCT));
        }
        else {
            srsran::console("ERROR There is no ctxt\n");
            return SRSRAN_ERROR;
        }
        srsran::console("GUTI_v: %x\n", ctxt.guti.m_tmsi);
    }
    else if (conf_field.compare("imei_v") == 0) {
        detach_req.eps_mobile_id.type_of_id = LIBLTE_MME_EPS_MOBILE_ID_TYPE_IMEI;
        usim_test->get_imei_vec(detach_req.eps_mobile_id.imei, 15);
        srsran::console("IMEI_v: %s\n", usim_test->get_imei_str().c_str());
    }
    else {
        return SRSRAN_ERROR;
    }

    // tsc_flag
    find_key = "tsc_flag";
    if (!tmsg.conf_map.count(find_key)) {
        srsran::console("\"%s\" is missing in \"%s\" file\n", find_key.c_str(), tmsg.current_file.c_str());
        return SRSRAN_ERROR;
    }
    conf_field = tmsg.conf_map[find_key];
    log_stream << "TSC Flag: " << conf_field.c_str() << std::endl;

    srsran::console("TSC Flag: %s\n", conf_field.c_str());
    if (conf_field.compare("native") == 0) {
        detach_req.nas_ksi.tsc_flag = LIBLTE_MME_TYPE_OF_SECURITY_CONTEXT_FLAG_NATIVE;
    }
    else if (conf_field.compare("mapped") == 0) {
        detach_req.nas_ksi.tsc_flag = LIBLTE_MME_TYPE_OF_SECURITY_CONTEXT_FLAG_MAPPED;
    }
    else {
        return SRSRAN_ERROR;
    }

    // ksi
    find_key = "ksi";
    if (!tmsg.conf_map.count(find_key)) {
        srsran::console("\"%s\" is missing in \"%s\" file\n", find_key.c_str(), tmsg.current_file.c_str());
        return SRSRAN_ERROR;
    }
    conf_field = tmsg.conf_map[find_key];
    log_stream << "KSI: " << conf_field.c_str() << std::endl;

    srsran::console("KSI: %s\n", conf_field.c_str());
    if (conf_field.compare("7") == 0) {
        detach_req.nas_ksi.nas_ksi = 7;
    }
    else if (conf_field.compare("valid") == 0) {
        if (have_guti && have_ctxt) {
            detach_req.nas_ksi.nas_ksi = ctxt.ksi;
        }
        else {
            detach_req.nas_ksi.nas_ksi = 3;
        }
    }
    else if (conf_field.compare("invalid") == 0) {
        if (have_guti && have_ctxt) {
            detach_req.nas_ksi.nas_ksi = (ctxt.ksi+1)%7;
        }
        else {
            detach_req.nas_ksi.nas_ksi = 3;
        }
    }
    else {
        return SRSRAN_ERROR;
    }

    log_stream << "----------------------------------------\n" << std::endl;
    ofs.close();

    srsran::console("---------------------------End <%s>-----------------------------\n", __func__);
    return SRSRAN_SUCCESS;
}

int test::gen_test_attach_complete(LIBLTE_MME_ACTIVATE_DEFAULT_EPS_BEARER_CONTEXT_ACCEPT_MSG_STRUCT &esm_context)
{
    srsran::console("---------------------------Start <%s> ---------------------------\n", __func__);
    srsran::console("Test Message Number: %d\n", tmsg.current_cnt+1);

    tmsg.current_cnt++;

    srsran::console("Test File Name: %s\n", tmsg.current_file.c_str());

    std::string conf_field;
    std::string find_key;

    log_stream << "\n---------- Test Configuration ----------" << std::endl;
    log_stream << tmsg.current_file.c_str() << std::endl;
    log_stream << "Message Type: " << tmsg.conf_map["msg_type"].c_str() << std::endl;

    //For logging MAC and Security Header Typegen_test_attach
    find_key = "mac_value";
    if (!tmsg.conf_map.count(find_key)) {
        srsran::console("\"%s\" is missing in \"%s\" file\n", find_key.c_str(), tmsg.current_file.c_str());
        return SRSRAN_ERROR;
    }
    tmsg.mac_flag = tmsg.conf_map[find_key];
    log_stream << "MAC Value: " << tmsg.mac_flag.c_str() << std::endl;

    // security_header_type
    find_key = "security_header_type";
    if (!tmsg.conf_map.count(find_key)) {
        srsran::console("\"%s\" is missing in \"%s\" file\n", find_key.c_str(), tmsg.current_file.c_str());
        return SRSRAN_ERROR;
    }
    conf_field = tmsg.conf_map[find_key];
    log_stream << "Security Header Type: " << conf_field.c_str() << std::endl;

    // parse_msg_conf(conf_file);
    if (tmsg.conf_map["msg_type"].compare("attach_complete") != 0)
    {
        srsran::console("Error:: msg_type mismatch with (attach_complete)\n");
        tmsg.current_cnt--;
        return SRSRAN_ERROR;
    }

    find_key = "sqn";
    if (!tmsg.conf_map.count(find_key)) {
        srsran::console("\"%s\" is missing in \"%s\" file\n", find_key.c_str(), tmsg.current_file.c_str());
        return SRSRAN_ERROR;
    }
    conf_field = tmsg.conf_map[find_key];
    log_stream << "sqn: " << conf_field.c_str() << std::endl;

    // bearer_id
    find_key = "bearer_id";
    if (!tmsg.conf_map.count(find_key)) {
        srsran::console("\"%s\" is missing in \"%s\" file\n", find_key.c_str(), tmsg.current_file.c_str());
        return SRSRAN_ERROR;
    }
    conf_field = tmsg.conf_map[find_key];
    log_stream << "Bearer ID: " << conf_field.c_str() << std::endl;

    srsran::console("Bearer ID: %s\n", conf_field.c_str());
    if (conf_field.compare("0") == 0) {
        esm_context.eps_bearer_id = 0;
    }
    else if (conf_field.compare("1") == 0) {
        esm_context.eps_bearer_id = 1;
    }
    else if (conf_field.compare("valid") == 0) {
        esm_context.eps_bearer_id = tmsg.bearer_id;
    }
    else if (conf_field.compare("invalid") == 0) {
        esm_context.eps_bearer_id = tmsg.bearer_id+1;
    }
    else {
        return SRSRAN_ERROR;
    }

    // tran_id
    find_key = "tran_id";
    if (!tmsg.conf_map.count(find_key)) {
        srsran::console("\"%s\" is missing in \"%s\" file\n", find_key.c_str(), tmsg.current_file.c_str());
        return SRSRAN_ERROR;
    }
    conf_field = tmsg.conf_map[find_key];
    log_stream << "Transaction ID: " << conf_field.c_str() << std::endl;

    srsran::console("Transaction ID: %s\n", conf_field.c_str());
    if (conf_field.compare("0") == 0) {
        esm_context.proc_transaction_id = 0;
    }
    else if (conf_field.compare("valid") == 0) {
        esm_context.proc_transaction_id = tmsg.transaction_id;
    }
    else if (conf_field.compare("invalid") == 0) {
        esm_context.proc_transaction_id = tmsg.transaction_id+1;
    }
    else if (conf_field.compare("reserved") == 0) {
        esm_context.proc_transaction_id = 0xff;
    }
    else {
        return SRSRAN_ERROR;
    }


    log_stream << "----------------------------------------\n" << std::endl;
    ofs.close();

    srsran::console("---------------------------End <%s>-----------------------------\n", __func__);
    return SRSRAN_SUCCESS;
}

int test::gen_test_sec_mode_complete(LIBLTE_MME_SECURITY_MODE_COMPLETE_MSG_STRUCT &sec_mode_comp, srsue::nas_base::nas_sec_ctxt ctxt)
{
    srsran::console("---------------------------Start <%s> ---------------------------\n", __func__);
    srsran::console("Test Message Number: %d\n", tmsg.current_cnt+1);

    tmsg.current_cnt++;

    srsran::console("Test File Name: %s\n", tmsg.current_file.c_str());

    std::string conf_field;
    std::string find_key;

    log_stream << "\n---------- Test Configuration ----------" << std::endl;
    log_stream << tmsg.current_file.c_str() << std::endl;
    log_stream << "Message Type: " << tmsg.conf_map["msg_type"].c_str() << std::endl;

    //For logging MAC and Security Header Type
    find_key = "mac_value";
    if (!tmsg.conf_map.count(find_key)) {
        srsran::console("\"%s\" is missing in \"%s\" file\n", find_key.c_str(), tmsg.current_file.c_str());
        return SRSRAN_ERROR;
    }
    tmsg.mac_flag = tmsg.conf_map[find_key];
    log_stream << "MAC Value: " << tmsg.mac_flag.c_str() << std::endl;

    // security_header_type
    find_key = "security_header_type";
    if (!tmsg.conf_map.count(find_key)) {
        srsran::console("\"%s\" is missing in \"%s\" file\n", find_key.c_str(), tmsg.current_file.c_str());
        return SRSRAN_ERROR;
    }
    conf_field = tmsg.conf_map[find_key];
    log_stream << "Security Header Type: " << conf_field.c_str() << std::endl;

    if (tmsg.conf_map["msg_type"].compare("security_mode_complete") != 0)
    {
        srsran::console("Error:: msg_type mismatch with (security_mode_complete)\n");
        tmsg.current_cnt--;
        return SRSRAN_ERROR;
    }

    find_key = "sqn";
    if (!tmsg.conf_map.count(find_key)) {
        srsran::console("\"%s\" is missing in \"%s\" file\n", find_key.c_str(), tmsg.current_file.c_str());
        return SRSRAN_ERROR;
    }
    conf_field = tmsg.conf_map[find_key];
    log_stream << "sqn: " << conf_field.c_str() << std::endl;

    // mobile_identity
    find_key = "mobile_identity";
    if (!tmsg.conf_map.count(find_key)) {
        srsran::console("\"%s\" is missing in \"%s\" file\n", find_key.c_str(), tmsg.current_file.c_str());
        return SRSRAN_ERROR;
    }
    conf_field = tmsg.conf_map[find_key];

    srsran::console("Mobile Identity: %s\n", conf_field.c_str());
    log_stream << "Mobile Identity: " << conf_field.c_str() << std::endl;
    sec_mode_comp.imeisv_present = true;
    if (conf_field.compare("imsi_v") == 0) {
        sec_mode_comp.imeisv.type_of_id = LIBLTE_MME_MOBILE_ID_TYPE_IMSI;
        usim_test->get_imsi_vec(sec_mode_comp.imeisv.imsi, 15);
        srsran::console("IMSI_v: %s\n", usim_test->get_imsi_str().c_str());
    }
    else if (conf_field.compare("imei_v") == 0) {
        sec_mode_comp.imeisv.type_of_id = LIBLTE_MME_MOBILE_ID_TYPE_IMEI;
        usim_test->get_imei_vec(sec_mode_comp.imeisv.imei, 15);
        srsran::console("IMEI_v: %s\n", usim_test->get_imei_str().c_str());
    }
    else if (conf_field.compare("imeisv_v") == 0) {
        sec_mode_comp.imeisv.type_of_id = LIBLTE_MME_MOBILE_ID_TYPE_IMEISV;
        usim_test->get_imei_vec(sec_mode_comp.imeisv.imeisv, 15);
        sec_mode_comp.imeisv.imeisv[14] = 0;
        sec_mode_comp.imeisv.imeisv[15] = 1;
        srsran::console("IMEISV_a: %s01\n", usim_test->get_imei_str().c_str());
    }
    else if (conf_field.compare("tmsi_v") == 0) {
        sec_mode_comp.imeisv.type_of_id = LIBLTE_MME_MOBILE_ID_TYPE_TMSI;
        sec_mode_comp.imeisv.tmsi = ctxt.guti.m_tmsi;
        srsran::console("TMSI_v: %x\n", ctxt.guti.m_tmsi);
    }
    else {
        return SRSRAN_ERROR;
    }


    log_stream << "----------------------------------------\n" << std::endl;
    ofs.close();

    srsran::console("---------------------------End <%s>-----------------------------\n", __func__);
    return SRSRAN_SUCCESS;
}

int test::gen_test_sec_mode_reject(LIBLTE_MME_SECURITY_MODE_REJECT_MSG_STRUCT &sec_mode_rej)
{
    srsran::console("---------------------------Start <%s> ---------------------------\n", __func__);
    srsran::console("Test Message Number: %d\n", tmsg.current_cnt+1);

    tmsg.current_cnt++;

    srsran::console("Test File Name: %s\n", tmsg.current_file.c_str());

    std::string conf_field;
    std::string find_key;

    log_stream << "\n---------- Test Configuration ----------" << std::endl;
    log_stream << tmsg.current_file.c_str() << std::endl;
    log_stream << "Message Type: " << tmsg.conf_map["msg_type"].c_str() << std::endl;

    //For logging MAC and Security Header Type
    find_key = "mac_value";
    if (!tmsg.conf_map.count(find_key)) {
        srsran::console("\"%s\" is missing in \"%s\" file\n", find_key.c_str(), tmsg.current_file.c_str());
        return SRSRAN_ERROR;
    }
    tmsg.mac_flag = tmsg.conf_map[find_key];
    log_stream << "MAC Value: " << tmsg.mac_flag.c_str() << std::endl;

    // security_header_type
    find_key = "security_header_type";
    if (!tmsg.conf_map.count(find_key)) {
        srsran::console("\"%s\" is missing in \"%s\" file\n", find_key.c_str(), tmsg.current_file.c_str());
        return SRSRAN_ERROR;
    }
    conf_field = tmsg.conf_map[find_key];
    log_stream << "Security Header Type: " << conf_field.c_str() << std::endl;

    if (tmsg.conf_map["msg_type"].compare("security_mode_reject") != 0)
    {
        srsran::console("Error:: msg_type mismatch with (security_mode_reject)\n");
        tmsg.current_cnt--;
        return SRSRAN_ERROR;
    }

    find_key = "sqn";
    if (!tmsg.conf_map.count(find_key)) {
        srsran::console("\"%s\" is missing in \"%s\" file\n", find_key.c_str(), tmsg.current_file.c_str());
        return SRSRAN_ERROR;
    }
    conf_field = tmsg.conf_map[find_key];
    log_stream << "sqn: " << conf_field.c_str() << std::endl;

    // emm_cause
    find_key = "emm_cause";
    if (!tmsg.conf_map.count(find_key)) {
        srsran::console("\"%s\" is missing in \"%s\" file\n", find_key.c_str(), tmsg.current_file.c_str());
        return SRSRAN_ERROR;
    }
    conf_field = tmsg.conf_map[find_key];
    srsran::console("EMM Cause: %s\n", conf_field.c_str());
    log_stream << "EMM Cause: " << conf_field.c_str() << std::endl;
    if (conf_field.compare("sec_cap_mismatch") == 0) {
        sec_mode_rej.emm_cause = LIBLTE_MME_EMM_CAUSE_UE_SECURITY_CAPABILITIES_MISMATCH;
    }
    else if (conf_field.compare("sec_mode_reject_unspecified") == 0) {
        sec_mode_rej.emm_cause = LIBLTE_MME_EMM_CAUSE_SECURITY_MODE_REJECTED_UNSPECIFIED;
    }
    else {
        return SRSRAN_ERROR;
    }


    log_stream << "----------------------------------------\n" << std::endl;
    ofs.close();

    srsran::console("---------------------------End <%s>-----------------------------\n", __func__);
    return SRSRAN_SUCCESS;
}

int test::gen_test_service_request(LIBLTE_MME_SERVICE_REQUEST_MSG_STRUCT &service_req, srsue::nas_base::nas_sec_ctxt ctxt, const uint32_t tx_count)
{
    srsran::console("---------------------------Start <%s> ---------------------------\n", __func__);
    srsran::console("Test Message Number: %d\n", tmsg.current_cnt+1);

    tmsg.current_cnt++;

    srsran::console("Test File Name: %s\n", tmsg.current_file.c_str());

    std::string conf_field;
    std::string find_key;

    log_stream << "\n---------- Test Configuration ----------" << std::endl;
    log_stream << tmsg.current_file.c_str() << std::endl;
    log_stream << "Message Type: " << tmsg.conf_map["msg_type"].c_str() << std::endl;

    find_key = "sqn";
    if (!tmsg.conf_map.count(find_key)) {
        srsran::console("\"%s\" is missing in \"%s\" file\n", find_key.c_str(), tmsg.current_file.c_str());
        return SRSRAN_ERROR;
    }
    conf_field = tmsg.conf_map[find_key];
    log_stream << "sqn: " << conf_field.c_str() << std::endl;

    //For logging MAC and Security Header Type
    find_key = "mac_value";
    if (!tmsg.conf_map.count(find_key)) {
        srsran::console("\"%s\" is missing in \"%s\" file\n", find_key.c_str(), tmsg.current_file.c_str());
        return SRSRAN_ERROR;
    }
    tmsg.mac_flag = tmsg.conf_map[find_key];
    log_stream << "MAC Value: " << tmsg.mac_flag.c_str() << std::endl;

    // security_header_type
    find_key = "security_header_type";
    if (!tmsg.conf_map.count(find_key)) {
        srsran::console("\"%s\" is missing in \"%s\" file\n", find_key.c_str(), tmsg.current_file.c_str());
        return SRSRAN_ERROR;
    }
    conf_field = tmsg.conf_map[find_key];
    tmsg.sec_hdr = LIBLTE_MME_SECURITY_HDR_TYPE_SERVICE_REQUEST;  // force security header for service request
    log_stream << "Security Header Type: " << conf_field.c_str() << std::endl;

    if (tmsg.conf_map["msg_type"].compare("service_request") != 0)
    {
        srsran::console("Error:: msg_type mismatch with (service_request)\n");
        tmsg.current_cnt--;
        return SRSRAN_ERROR;
    }

    // ksi
    find_key = "ksi";
    if (!tmsg.conf_map.count(find_key)) {
        srsran::console("\"%s\" is missing in \"%s\" file\n", find_key.c_str(), tmsg.current_file.c_str());
        return SRSRAN_ERROR;
    }
    conf_field = tmsg.conf_map[find_key];
    srsran::console("KSI: %s\n", conf_field.c_str());
    log_stream << "KSI: " << conf_field.c_str() << std::endl;
    if (conf_field.compare("7") == 0) {
        service_req.ksi_and_seq_num.ksi = 7;
    }
    else if (conf_field.compare("valid") == 0) {
        service_req.ksi_and_seq_num.ksi = ctxt.ksi;
    }
    else if (conf_field.compare("invalid") == 0) {
        service_req.ksi_and_seq_num.ksi = (ctxt.ksi+1)%7;
    }
    else {
        return SRSRAN_ERROR;
    }

    // sqn
    find_key = "sqn";
    if (!tmsg.conf_map.count(find_key)) {
        srsran::console("\"%s\" is missing in \"%s\" file\n", find_key.c_str(), tmsg.current_file.c_str());
        return SRSRAN_ERROR;
    }
    conf_field = tmsg.conf_map[find_key];
    srsran::console("Sequence Number: %s\n", conf_field.c_str());
    log_stream << "Sequence Number: " << conf_field.c_str() << std::endl;
    if (conf_field.compare("valid") == 0) {
        service_req.ksi_and_seq_num.seq_num = tx_count & 0x1Fu;
    }
    else if (conf_field.compare("invalid") == 0) {
        service_req.ksi_and_seq_num.seq_num = 0;
    }
    else {
        return SRSRAN_ERROR;
    }

    // short_mac
    find_key = "short_mac";
    if (!tmsg.conf_map.count(find_key)) {
        srsran::console("\"%s\" is missing in \"%s\" file\n", find_key.c_str(), tmsg.current_file.c_str());
        return SRSRAN_ERROR;
    }
    conf_field = tmsg.conf_map[find_key];
    srsran::console("Short MAC: %s\n", conf_field.c_str());
    log_stream << "Short MAC: " << conf_field.c_str() << std::endl;
    if (conf_field.compare("valid") == 0) {
        srsran::console("Valid short MAC is not implemented\n");
    }
    else if (conf_field.compare("invalid") == 0) {
        service_req.short_mac = (uint16)32767;
    }
    else {
        return SRSRAN_ERROR;
    }


    log_stream << "----------------------------------------\n" << std::endl;
    ofs.close();

    srsran::console("---------------------------End <%s>-----------------------------\n", __func__);
    return SRSRAN_SUCCESS;
}

int test::gen_test_tau_request(LIBLTE_MME_TRACKING_AREA_UPDATE_REQUEST_MSG_STRUCT &tau_req, srsue::nas_base::nas_sec_ctxt ctxt)
{
    srsran::console("<%s> log stream open---------------------------\n", __func__);
    srsran::console("---------------------------Start <%s> ---------------------------\n", __func__);
    srsran::console("Test Message Number: %d\n", tmsg.current_cnt+1);

    tmsg.current_cnt++;
    std::string conf_field;
    std::string find_key;
    
    srsran::console("Test File Name: %s\n", tmsg.current_file.c_str());
    srsran::console("Log File Name: %s\n", tmsg.logfile.c_str());

    log_stream << "\n---------- Test Configuration ----------" << std::endl;
    log_stream << tmsg.current_file.c_str() << std::endl;
    log_stream << "Message Type: " << tmsg.conf_map["msg_type"].c_str() << std::endl;
    //For logging MAC and Security Header Type
    find_key = "mac_value";
    if (!tmsg.conf_map.count(find_key)) {
        srsran::console("\"%s\" is missing in \"%s\" file\n", find_key.c_str(), tmsg.current_file.c_str());
        return SRSRAN_ERROR;
    }
    tmsg.mac_flag = tmsg.conf_map[find_key];
    log_stream << "MAC Value: " << tmsg.mac_flag.c_str() << std::endl;
    // security_header_type
    find_key = "security_header_type";
    if (!tmsg.conf_map.count(find_key)) {
        srsran::console("\"%s\" is missing in \"%s\" file\n", find_key.c_str(), tmsg.current_file.c_str());
        return SRSRAN_ERROR;
    }
    conf_field = tmsg.conf_map[find_key];
    log_stream << "Security Header Type: " << conf_field.c_str() << std::endl;
    find_key = "sqn";
    if (!tmsg.conf_map.count(find_key)) {
        srsran::console("\"%s\" is missing in \"%s\" file\n", find_key.c_str(), tmsg.current_file.c_str());
        return SRSRAN_ERROR;
    }
    conf_field = tmsg.conf_map[find_key];
    log_stream << "sqn: " << conf_field.c_str() << std::endl;
    if (tmsg.conf_map["msg_type"].compare("tau_request") != 0)
    {
        srsran::console("Error:: msg_type mismatch with (tau_request)\n");
        tmsg.current_cnt--;
        return SRSRAN_ERROR;
    }
    // active_flag
    find_key = "active_flag";
    if (!tmsg.conf_map.count(find_key)) {
        srsran::console("\"%s\" is missing in \"%s\" file\n", find_key.c_str(), tmsg.current_file.c_str());
        return SRSRAN_ERROR;
    }
    conf_field = tmsg.conf_map[find_key];
    srsran::console("Active Flag: %s\n", conf_field.c_str());
    //For logging configuration
    log_stream << "Active Flag: " << conf_field.c_str() << std::endl;
    if (conf_field.compare("bearer") == 0) {
        tau_req.eps_update_type.active_flag = true;
    }
    else if (conf_field.compare("no_bearer") == 0) {
        tau_req.eps_update_type.active_flag = false;
    }
    else {
        return SRSRAN_ERROR;
    }
    // update_type
    find_key = "update_type";
    if (!tmsg.conf_map.count(find_key)) {
        srsran::console("\"%s\" is missing in \"%s\" file\n", find_key.c_str(), tmsg.current_file.c_str());
        return SRSRAN_ERROR;
    }
    conf_field = tmsg.conf_map[find_key];
    srsran::console("Update Type: %s\n", conf_field.c_str());
    //For logging configuration
    log_stream << "Update Type: " << conf_field.c_str() << std::endl;
    if (conf_field.compare("ta") == 0) {
        tau_req.eps_update_type.type = LIBLTE_MME_EPS_UPDATE_TYPE_TA_UPDATING;
    }
    else if (conf_field.compare("combined") == 0) {
        tau_req.eps_update_type.type = LIBLTE_MME_EPS_UPDATE_TYPE_COMBINED_TA_LA_UPDATING;
    }
    else if (conf_field.compare("combined_w_imsi") == 0) {
        tau_req.eps_update_type.type = LIBLTE_MME_EPS_UPDATE_TYPE_COMBINED_TA_LA_UPDATING_WITH_IMSI_ATTACH;
    }
    else if (conf_field.compare("periodic") == 0) {
        tau_req.eps_update_type.type = LIBLTE_MME_EPS_UPDATE_TYPE_PERIODIC_UPDATING;
    }
    else {
        return SRSRAN_ERROR;
    }
    // tsc_flag
    find_key = "tsc_flag";
    if (!tmsg.conf_map.count(find_key)) {
        srsran::console("\"%s\" is missing in \"%s\" file\n", find_key.c_str(), tmsg.current_file.c_str());
        return SRSRAN_ERROR;
    }
    conf_field = tmsg.conf_map[find_key];
    log_stream << "TSC Flag: " << conf_field.c_str() << std::endl;
    srsran::console("TSC Flag: %s\n", conf_field.c_str());
    if (conf_field.compare("native") == 0) {
        tau_req.nas_ksi.tsc_flag = LIBLTE_MME_TYPE_OF_SECURITY_CONTEXT_FLAG_NATIVE;
    }
    else if (conf_field.compare("mapped") == 0) {
        tau_req.nas_ksi.tsc_flag = LIBLTE_MME_TYPE_OF_SECURITY_CONTEXT_FLAG_MAPPED;
    }
    else {
        return SRSRAN_ERROR;
    }
    // ksi
    find_key = "ksi";
    if (!tmsg.conf_map.count(find_key)) {
        srsran::console("\"%s\" is missing in \"%s\" file\n", find_key.c_str(), tmsg.current_file.c_str());
        return SRSRAN_ERROR;
    }
    conf_field = tmsg.conf_map[find_key];
    log_stream << "KSI: " << conf_field.c_str() << std::endl;
    srsran::console("KSI: %s\n", conf_field.c_str());
    if (conf_field.compare("7") == 0) {
        tau_req.nas_ksi.nas_ksi = 7;
    }
    else if (conf_field.compare("valid") == 0) {
        tau_req.nas_ksi.nas_ksi = ctxt.ksi;
    }
    else if (conf_field.compare("invalid") == 0) {
        tau_req.nas_ksi.nas_ksi = (ctxt.ksi+1)%7;
    }
    else {
        return SRSRAN_ERROR;
    }
    // old_guti
    find_key = "old_guti";
    if (!tmsg.conf_map.count(find_key)) {
        srsran::console("\"%s\" is missing in \"%s\" file\n", find_key.c_str(), tmsg.current_file.c_str());
        return SRSRAN_ERROR;
    }
    conf_field = tmsg.conf_map[find_key];
    log_stream << "Old GUTI: " << conf_field.c_str() << std::endl;
    srsran::console("Old GUTI: %s\n", conf_field.c_str());
    if (conf_field.compare("imsi_v") == 0) {
        tau_req.old_guti.type_of_id = LIBLTE_MME_EPS_MOBILE_ID_TYPE_IMSI;
        usim_test->get_imsi_vec(tau_req.old_guti.imsi, 15);
        srsran::console("IMSI_v: %s\n", usim_test->get_imsi_str().c_str());
    }
    else if (conf_field.compare("guti_v") == 0) {
        tau_req.old_guti.type_of_id = LIBLTE_MME_EPS_MOBILE_ID_TYPE_GUTI;
        memcpy(&tau_req.old_guti.guti, &ctxt.guti, sizeof(LIBLTE_MME_EPS_MOBILE_ID_GUTI_STRUCT));
        srsran::console("GUTI_v: %x\n", ctxt.guti.m_tmsi);
    }
    else if (conf_field.compare("imei_v") == 0) {
        tau_req.old_guti.type_of_id = LIBLTE_MME_EPS_MOBILE_ID_TYPE_IMEI;
        usim_test->get_imei_vec(tau_req.old_guti.imei, 15);
        srsran::console("IMEI_v: %s\n", usim_test->get_imei_str().c_str());
    }
    else {
        return SRSRAN_ERROR;
    }
    log_stream << "----------------------------------------\n" << std::endl;
    ofs.close();
    srsran::console("---------------------------End <%s>-----------------------------\n", __func__);
    return SRSRAN_SUCCESS;
}

bool test::check_test_num()
{
    srsran::console("[debug] Test Count: %d / %d\n", tmsg.current_cnt+1, tmsg.tmsg_cnt);
    if (tmsg.current_cnt >= tmsg.tmsg_cnt) return false;
    else return true;
}


// Generate key from attacker context
srsue::auth_result_t test::attacker_generate_authentication_response(uint8_t* rand,
                                                     uint8_t* autn_enb,
                                                     uint16_t mcc,
                                                     uint16_t mnc,
                                                     uint8_t* res,
                                                     int*     res_len,
                                                     uint8_t* k_asme_)
{
    auth_result_t auth_result;
    uint8_t       ak_xor_sqn[6];

    auth_result = attacker_gen_auth_res_milenage(rand, autn_enb, res, res_len, ak_xor_sqn);


    if (auth_result == AUTH_OK) {
        // Generate K_asme
        security_generate_k_asme(tmsg.attacker_usim.ck, tmsg.attacker_usim.ik, ak_xor_sqn, mcc, mnc, k_asme_);
    }
    return auth_result;
}

srsue::auth_result_t
test::attacker_gen_auth_res_milenage(uint8_t* rand, uint8_t* autn_enb, uint8_t* res, int* res_len, uint8_t* ak_xor_sqn)
{
    auth_result_t result = AUTH_OK;
    uint32_t      i;
    uint8_t       sqn[6];

    // Use RAND and K to compute RES, CK, IK and AK
    security_milenage_f2345(tmsg.attacker_usim.k, tmsg.attacker_usim.opc, rand, res, tmsg.attacker_usim.ck, tmsg.attacker_usim.ik, tmsg.attacker_usim.ak);

    *res_len = 8;

    // Extract sqn from autn
    for (i = 0; i < 6; i++) {
        sqn[i] = autn_enb[i] ^ tmsg.attacker_usim.ak[i];
    }
    // Extract AMF from autn
    for (int i = 0; i < 2; i++) {
        tmsg.attacker_usim.amf[i] = autn_enb[6 + i];
    }

    // Generate MAC
    security_milenage_f1(tmsg.attacker_usim.k, tmsg.attacker_usim.opc, rand, sqn, tmsg.attacker_usim.amf, tmsg.attacker_usim.mac);

    // Construct AUTN
    for (i = 0; i < 6; i++) {
        tmsg.attacker_usim.autn[i] = sqn[i] ^ tmsg.attacker_usim.ak[i];
    }
    for (i = 0; i < 2; i++) {
        tmsg.attacker_usim.autn[6 + i] = tmsg.attacker_usim.amf[i];
    }
    for (i = 0; i < 8; i++) {
        tmsg.attacker_usim.autn[8 + i] = tmsg.attacker_usim.mac[i];
    }

    // Compare AUTNs
    for (i = 0; i < 16; i++) {
        if (tmsg.attacker_usim.autn[i] != autn_enb[i]) {
        result = AUTH_FAILED;
        }
    }

    for (i = 0; i < 6; i++) {
        ak_xor_sqn[i] = sqn[i] ^ tmsg.attacker_usim.ak[i];
    }


    return result;
}



}