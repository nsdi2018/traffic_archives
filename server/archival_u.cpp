#include "Enclave_u.h"

#include "../common/data_type.h"

#include <fstream>
#include <pcap.h>
#include <pthread.h>
#include <time.h>
#include <unordered_map>

inline long time_elapsed_in_us(const timespec &start, const timespec &end) {
    return (end.tv_sec - start.tv_sec) * 1000000.0 +
        (end.tv_nsec - start.tv_nsec) / 1000.0;
}

extern pcap_t *pcap_handle;
extern std::ofstream logger;
extern int log_switch;

// flow buffer management
std::unordered_map<std::string, enc_flow_buffer_t> enc_flow_buffer;
// trick to avoid data marshalling
mgmt_buffer_flow_t mgmt_buffer_flow;
enc_flow_buffer_t enc_flow;

// keyword state management
std::unordered_map<std::string, enc_kw_state_t> enc_kw_state;
pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

/* ocall functions */
uint8_t* ocall_packet_capture(void *_pkt_info)
{
    static timespec start_time, stop_time;
    static int num_pkts, total_num_pkts;
    static double num_bytes;

    static pinfo pkt_info[BATCH_SIZE];
    static uint8_t batch[BATCH_SIZE][MAX_PACKET_LEN];

    static pcap_pkthdr pheader;
    int count = 0;
    
    while (count != BATCH_SIZE) {
        const uint8_t *pkt = pcap_next(pcap_handle, &pheader);
        if (pkt) {// && pheader.len>HEADER_LEN) { // ETH + IP + TCP
            //printf("length %d %s\n", pheader.caplen, (char *)&pkt[PAYLOAD_OFFSET]);
            pkt_info[count].timestamp = pheader.ts.tv_sec;
            pkt_info[count].ip_proto = *(pkt + IP_OFFSET + 9);
            if (pkt_info[count].ip_proto != IP_PROTO_TCP &&
                pkt_info[count].ip_proto != IP_PROTO_UDP) {
                continue;
            }
            pkt_info[count].pkt_len = pheader.caplen - IP_OFFSET;
            memcpy(batch[count], pkt + IP_OFFSET, pkt_info[count].pkt_len);
            ++count;

            num_bytes += pheader.caplen;
            ++num_pkts;

            //printf("%d\n", pheader.caplen);
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
    //printf("received!\n");
    memcpy(_pkt_info, &pkt_info[0], sizeof(pinfo)*BATCH_SIZE);

    return &batch[0][0];
}

void ocall_flow_timeout(int crt_time)
{
    printf("before flow timeout checking %d\n", enc_flow_buffer.size());
    for (auto it = enc_flow_buffer.begin(); it != enc_flow_buffer.end();) {
        if ((crt_time - it->second.init_time) >= FLOW_TIMEOUT)
            it = enc_flow_buffer.erase(it);
        else
            ++it;
    }
    printf("after flow timeout checking %d\n", enc_flow_buffer.size());
}

void ocall_store(void *hid,
    void *token_list,
    void *eid_list,
    void *enc_flow, int flow_size,
    void *mac)
{
    // TODO
}

/* state management */
void ocall_mgmt_flow_fetch(const void *_enc_fid)
{
    std::string enc_fid((byte *)_enc_fid, FID_SIZE);

    // debug
    if (enc_flow_buffer.count(enc_fid) == 0) {
        printf("[*] holy!\n");
        exit(1);
    }

    memcpy(&enc_flow, &enc_flow_buffer[enc_fid], sizeof(enc_flow_buffer_t));

    enc_flow_buffer.erase(enc_fid);
}

void ocall_mgmt_flow_flush()
{
    //printf("flushed!\n");
    std::string enc_fid(FID_SIZE, 0);
    for (int i = 0; i < BATCH_SIZE; ++i) {
        // skip completed flow
        if (mgmt_buffer_flow.pkt_size_list[i] == 0) {
            continue;
        }

        enc_fid.assign(&mgmt_buffer_flow.enc_fid_list[i][0], FID_SIZE);

        enc_flow_buffer_t &enc_flow = enc_flow_buffer[enc_fid];

        int crt_idx = enc_flow.pkt_count;

        enc_flow.pkt_size_list[crt_idx] = mgmt_buffer_flow.pkt_size_list[i];
        enc_flow.ip_proto_list[crt_idx] = mgmt_buffer_flow.ip_proto_list[i];

        memcpy(&enc_flow.stream[enc_flow.stream_size],
            &mgmt_buffer_flow.enc_pkt_list[i],
            mgmt_buffer_flow.pkt_size_list[i]);
        enc_flow.stream_size += mgmt_buffer_flow.pkt_size_list[i];

        enc_flow.mac_list[crt_idx] = mgmt_buffer_flow.mac_list[i];

        ++enc_flow.pkt_count;
    }

    /*if (log_switch == 0 && 
        enc_flow_buffer.size() > LOG_THRESHOLD &&
        enc_kw_state.size() > 1000000) {
        printf("log upon %d flows\n", enc_flow_buffer.size());
        log_switch = 1;
    }*/
}

void ocall_mgmt_kw_fetch(const void *_enc_kw_list, int kw_count,
    void *_rlt,
    void *_enc_kw_state_list,
    void *_mac_list)
{
    byte *rlt = (byte *)_rlt;
    enc_kw_t *enc_kw_list = (keyword_t *)_enc_kw_list;
    kw_state_t *enc_kw_state_list = (kw_state_t *)_enc_kw_state_list;
    mac_t *mac_list = (mac_t *)_mac_list;

#if MULTI_THREAD==1
    pthread_mutex_lock(&mutex);
#endif
    std::string enc_kw(KW_SIZE, 0);
    for (int i = 0; i < kw_count; ++i) {
        enc_kw = KW_TO_STR(enc_kw_list[i]);

        if (enc_kw_state.count(enc_kw) == 0) {
            rlt[i] = KW_FETCH_NEG;
        }
        else {
            enc_kw_state_t &state = enc_kw_state[enc_kw];
            
            enc_kw_state_list[i] = state.kw_state;
            mac_list[i] = state.mac;
            rlt[i] = KW_FETCH_POS;
        }
    }
#if MULTI_THREAD==1
    pthread_mutex_unlock(&mutex);
#endif
}

void ocall_mgmt_kw_store(const void *_enc_kw_list, int kw_count,
    const void *_enc_kw_state_list,
    const void *_mac_list)
{
    enc_kw_t *enc_kw_list = (keyword_t *)_enc_kw_list;
    kw_state_t *enc_kw_state_list = (kw_state_t *)_enc_kw_state_list;
    mac_t *mac_list = (mac_t *)_mac_list;

#if MULTI_THREAD==1
    pthread_mutex_lock(&mutex);
#endif
    std::string enc_kw(KW_SIZE, 0);
    for (int i = 0; i < kw_count; ++i) {
        enc_kw = KW_TO_STR(enc_kw_list[i]);
        enc_kw_state_t &state = enc_kw_state[enc_kw];

        state.kw_state = enc_kw_state_list[i];
        state.mac = mac_list[i];
    }

    /*if (enc_kw_state.size() > LOG_THRESHOLD) {
        printf("log upon %d keywords\n", enc_kw_state.size());
        log_switch = 1;
    }*/
#if MULTI_THREAD==1
    pthread_mutex_unlock(&mutex);
#endif
}

void ocall_search_get_state(const void *_kw,
    void *_state,
    void *_mac)
{
    std::string enc_kw((byte*)_kw, KW_SIZE);
    enc_kw_state_t &state = enc_kw_state[enc_kw];
    memcpy(_state, &state.kw_state, sizeof(kw_state_t));
    memcpy(_mac, &state.mac, MAC_LEN);
}

void ocall_search_put_state(const void *_kw,
    void *_state,
    void *_mac)
{
    std::string enc_kw((byte*)_kw, KW_SIZE);
    kw_state_t *state = (kw_state_t *)_state;
    mac_t *mac = (mac_t *)_mac;

    pthread_mutex_lock(&mutex);
    enc_kw_state_t &enc_state = enc_kw_state[enc_kw];
    enc_state.kw_state = *state;
    enc_state.mac = *mac;
    pthread_mutex_unlock(&mutex);
}