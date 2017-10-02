#include "enclave_mgmt.h"

#include "Enclave_u.h"

#include "../common/config.h"
#include "../common/data_type.h"

#include <pcap.h>
#include <stdlib.h>
#include <thread>
#include <unordered_map>

/*  Global */
pcap_t *pcap_handle;
std::ofstream logger;
int log_switch = 0;

/* State management  */
extern std::unordered_map<std::string, enc_flow_buffer_t> enc_flow_buffer;
extern mgmt_buffer_flow_t mgmt_buffer_flow;
extern enc_flow_buffer_t enc_flow;
extern std::unordered_map<std::string, enc_kw_state_t> enc_kw_state;

void init(int argc, char *argv[])
{
    printf("[*] Initializing system ...\n");


    if (argc < 2) {
        printf("Expect output file!\n");
        exit(1);
    }

    printf("[*] Multi Thread mode is %s!\n", MULTI_THREAD ?"enabled":"disabled");
    if(MULTI_THREAD)
        printf("[*] %d threads are used!\n", THREAD_NUM);
    printf("[*] State management is %s!\n", STATE_MGMT ? "enabled" : "disabled");
    printf("[*] CCS'16 construction is %s!\n", CCS16 ? "used" : "unused");
#if LIVE_TRAFFIC==0
    if (argc < 3) {
        printf("Expect pcap file!\n");
        exit(1);
    }
    printf("[*] Read packets from %s\n", argv[2]);
#endif

    // pcap
    char errbuf[PCAP_ERRBUF_SIZE];
#if LIVE_TRAFFIC==1
    pcap_handle = pcap_open_live("eth0", SNAPLENGTH, 0, 500, errbuf);
#else
    pcap_handle = pcap_open_offline(argv[2], errbuf);
#endif
    if (pcap_handle == NULL) {
        printf("[!] Error pcap_open_*: %s \n", errbuf);
        exit(1);
    }
    struct bpf_program  cfilter;
    //const char bpff[] = "dst host 10.37.1.18";
    const char bpff[] = "src host 10.37.1.15 and (tcp or udp)";
    //const char bpff[] = "tcp or udp";
    if ((pcap_compile(pcap_handle, &cfilter, bpff, 1, PCAP_NETMASK_UNKNOWN)) == -1) {
        printf("[*] Error pcap_compile user_filter: %s\n", pcap_geterr(pcap_handle));
        exit(1);
    }
    if (pcap_setfilter(pcap_handle, &cfilter)) {
        printf("[*] Unable to set pcap filter!  %s", pcap_geterr(pcap_handle));
    }
    pcap_freecode(&cfilter);

//#define PCAP_BUFFER_SIZE 1024 //1M
//    pcap_set_buffer_size(pcap_handle, PCAP_BUFFER_SIZE);

    // enclave
    if (initialize_enclave() < 0) {
        printf("[*] Enclave initialization fails ...\n");
        printf("[*] Enter a character before exit ...\n");
        getchar();
        abort();
    }
    printf("[*] Enclave initialization succeeds! \n");

    // logger
    logger.open(argv[1]);
}

void producer_thread() 
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    printf("[*] Producer\n");
    ret = ecall_producer(global_eid);
    if (ret != SGX_SUCCESS) {
        printf("[*] Producer fails!\n");
        print_error_message(ret);
        exit(1);
    }
}

void consumer_thread() 
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    printf("[*] Consumer %d\n", std::this_thread::get_id());
    ret = ecall_consumer(global_eid);
    if (ret != SGX_SUCCESS) {
        printf("[*] Consumer %d fails!\n", std::this_thread::get_id());
        print_error_message(ret);
        exit(1);
    }
}

void single_thread()
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    printf("[*] Single thread\n");
    ret = ecall_single_thread(global_eid);
    if (ret != SGX_SUCCESS) {
        printf("[*] Single thread fails!\n");
        print_error_message(ret);
        exit(1);
    }
}

#include <vector>
std::vector<keyword_t> all_kw;
//std::unordered_map<std::string, kw_state_t> kw_state_table;
#define KW_SPACE_SIZE 5000000

//#define QUERY_SET_SIZE 100000
//std::vector<keyword_t> query_kw;

void add_kw() {
    std::ifstream in("./test_5m");
    std::string str;
    keyword_t kw;
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    int count = 0;
    while (in >> str) {
        //ecall_add_kw(global_eid, kw.c_str());
        if (str.size() != KW_SIZE)
            continue;
        memcpy(&kw, str.data(), KW_SIZE);
        all_kw[count] = kw;
        ++count;
        if (count % 50000 == 0)
            printf("%d\n", count);
    }
    
    ret = ecall_add_kw(global_eid, &enc_kw_state, all_kw.data(), all_kw.size());
    if (ret != SGX_SUCCESS) {
        printf("Fail to add kw!\n");
    }
    printf("%d keywords added db size %d\n\n", count, enc_kw_state.size());

    //query_kw.assign(all_kw.begin(), all_kw.begin() + QUERY_SET_SIZE);
    all_kw.clear();

    in.close();
}
inline long time_elapsed_in_ns(const timespec &start, const timespec &end) {
    return (end.tv_sec - start.tv_sec) * 1000000000.0 +
        (end.tv_nsec - start.tv_nsec);
}
//void index_test() {
//    printf("start test ...\n");
//    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
//    
//    timespec start_time, stop_time;
//    double thruput_ccs = 0, thruput_our = 0;
//#define TRIAL 5
//    for (int i = 0; i < TRIAL; ++i) {
//        clock_gettime(CLOCK_REALTIME, &start_time);
//        ret = ecall_index_test_ccs(global_eid, &kw_state_table, query_kw.data(), QUERY_SET_SIZE);
//        clock_gettime(CLOCK_REALTIME, &stop_time);
//        if (ret != SGX_SUCCESS) {
//            printf("Fail index test ccs!\n");
//        }
//        thruput_ccs += QUERY_SET_SIZE*1.0 / time_elapsed_in_ns(start_time, stop_time)*1000000000.0;
//
//        clock_gettime(CLOCK_REALTIME, &start_time);
//        ret = ecall_index_test_our(global_eid, &kw_state_table, query_kw.data(), QUERY_SET_SIZE);
//        clock_gettime(CLOCK_REALTIME, &stop_time);
//        if (ret != SGX_SUCCESS) {
//            printf("Fail index test our!\n");
//        }
//        thruput_our += QUERY_SET_SIZE*1.0 / time_elapsed_in_ns(start_time, stop_time)*1000000000.0;
//    }
//
//    printf("%d: ccs %f our %f\n", KW_SPACE_SIZE, thruput_ccs/ TRIAL, thruput_our/ TRIAL);
//}

void search_notify() {
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    // delay a few seconds to ensure keyword state contains data
    sleep(3);

    printf("[*] Start to notify!\n");
    while (true) {
        auto it = enc_kw_state.begin();
        std::advance(it, rand() % enc_kw_state.size());
        std::string kw = it->first;
        ret = ecall_search_notify(global_eid, kw.data());
        if (ret != SGX_SUCCESS) {
            printf("[*] Single thread fails!\n");
            print_error_message(ret);
            exit(1);
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
}

inline long time_elapsed_in_us(const timespec &start, const timespec &end) {
    return (end.tv_sec - start.tv_sec) * 1000000.0 +
        (end.tv_nsec - start.tv_nsec) / 1000.0;
}

void capture_test()
{
    static timespec start_time, stop_time;
    static int num_pkts, total_num_pkts;
    static double num_bytes;

    static pinfo pkt_info[BATCH_SIZE];
    static uint8_t batch[BATCH_SIZE][MAX_PACKET_LEN];

    pcap_pkthdr pheader;
    pcap_pkthdr *p_header;
    int count = 0;

    while (count != BATCH_SIZE) {
        const uint8_t *pkt = pcap_next(pcap_handle, &pheader);
        if (pkt) {// && pheader.len>HEADER_LEN) { // ETH + IP + TCP
                  //printf("length %d %s\n", pheader.caplen, (char *)&pkt[PAYLOAD_OFFSET]);
            pkt_info[count].timestamp = pheader.ts.tv_sec;
            pkt_info[count].ip_proto = *(pkt + IP_OFFSET + 9);
            /*if (pkt_info[count].ip_proto != IP_PROTO_TCP &&
                pkt_info[count].ip_proto != IP_PROTO_UDP) {
                continue;
            }*/
            pkt_info[count].pkt_len = pheader.caplen - IP_OFFSET;
            memcpy(batch[count], pkt + IP_OFFSET, pkt_info[count].pkt_len);
            ++count;

            num_bytes += pheader.caplen;
            ++num_pkts;

            //printf("%d\n", pheader.caplen);
            //if (num_pkts == 10)
            //    exit(0);
#define LOG_ITVL 100000
            if (num_pkts == LOG_ITVL) {
                clock_gettime(CLOCK_REALTIME, &stop_time);
                double thruput = num_bytes * 8 / time_elapsed_in_us(start_time, stop_time);
                printf("[*] thruput: %f Mbps flow: %lu kw: %lu #pkt: %d\n",
                    thruput, enc_flow_buffer.size(), enc_kw_state.size(), total_num_pkts);
                //if(log_switch)
                logger << thruput << std::endl;

                total_num_pkts += num_pkts;
                num_pkts = 0;
                num_bytes = 0;
                start_time = stop_time;
            }
        }
    }
}

// main loop
void start() 
{
  printf("[*] Running ...\n");
#if STATE_MGMT==1
  enc_flow_buffer.reserve(50000); // 50K
  enc_kw_state.reserve(5000000); // 5M
#endif
  sgx_status_t ret = ecall_init(global_eid, &log_switch, &mgmt_buffer_flow, &enc_flow);
  if (ret != SGX_SUCCESS) {
      printf("[*] Initialization fails!\n");
      print_error_message(ret);
      exit(1);
  }

  //while (true) {
  //    capture_test();
  //}
//#if STATE_MGMT==0
//  all_kw.resize(KW_SPACE_SIZE);
//  add_kw();
//#endif

#if MULTI_THREAD==0
  single_thread();
#else
  std::thread trd[THREAD_NUM];
  trd[0] = std::thread(producer_thread);
  sleep(1);

  for(int i=1; i<THREAD_NUM; ++i)
    trd[i] = std::thread(consumer_thread);

  //trd[THREAD_NUM] = std::thread(search_notify);

  for (int i = 0; i < THREAD_NUM; ++i)
      trd[i].join();
#endif

  /*all_kw.resize(KW_SPACE_SIZE);
  kw_state_table.reserve(KW_SPACE_SIZE);

  add_kw();
  index_test();*/
}

void stop(int sig) {
    printf("[*] Stopping system ...\n");

    /* Destroy the enclave */
    sgx_destroy_enclave(global_eid);

    printf("[*] Enclave successfully returned.\n");

    logger.close();

    if (pcap_handle) {
        pcap_close(pcap_handle);
    }

    exit(0);
}

/* Application entry */
int SGX_CDECL main(int argc, char *argv[])
{
  (void)(argc);
  (void)(argv);

  signal(SIGTERM, stop);
  signal(SIGQUIT, stop);
  signal(SIGTSTP, stop); // Ctrl + z
  signal(SIGINT, stop); // Ctrl + c
  //signal(SIGALRM, set_end_sessions);
  //signal(SIGUSR1, set_end_sessions);

  init(argc, argv);

  start();

  stop(SIGQUIT);
  return 0;
}