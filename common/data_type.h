#ifndef DATA_TYPE_H
#define DATA_TYPE_H

#include "config.h"
#include <stdint.h>

#include <algorithm>
#include <array>
#include <list>
#include <string>
#include <string.h>
#include <tuple>

/* for all sources except OCALL/ECALL */
typedef char byte;

/* packet related */
typedef struct pinfo_t {
    int pkt_len;    // L3 packet, in byte
    int timestamp;  // in second
    int ip_proto;   // tcp or udp
} pinfo;

typedef std::array<byte, MAX_PACKET_LEN> packet_t;

typedef struct batch {
    packet_t packet_list[BATCH_SIZE];
    pinfo_t info_list[BATCH_SIZE];
} batch_t;

/* crypto related */
#define KEY_LEN 16 // 128-bit

#define MAC_LEN 16
typedef std::array<byte, MAC_LEN> mac_t;

#define RAND_LEN 256 // 2048-bit
typedef std::array<byte, RAND_LEN> rand_t;

/* flow related */
struct fid {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t proto;
}; // not used, for reference only
#define FID_SIZE 13 // for alignment, indeed 13
typedef std::string fid_t; // for use of map key

#define MAX_PKT_PER_BUFFER 1024
typedef struct flow_buffer {
    byte stream[MSS];
    int  pkt_size_list[MAX_PKT_PER_BUFFER]; // 4K
    byte ip_proto_list[MAX_PKT_PER_BUFFER]; // 1K
} flow_buffer_t;

typedef struct flow_state {
    int pkt_count;
    int flow_size;
    int init_time;
} flow_state_t;

/* indexing related */
typedef std::tuple<fid_t, flow_state_t, flow_buffer_t> ready_flow_t;

#define KW_SIZE 8
typedef std::array<byte, KW_SIZE> keyword_t;
#define KW_TO_STR(kw) std::string(&kw[0], KW_SIZE)

typedef struct kw_state {
    int counter;
    rand_t rand;
} kw_state_t;

#define TOKEN_LEN 16 // 128-bit
typedef std::array<byte, TOKEN_LEN> token_t;

#define HID_LEN 16
typedef std::array<byte, HID_LEN> hid_t;

#define EID_LEN HID_LEN
typedef std::array<byte, EID_LEN> eid_t;
typedef std::array<token_t, PER_FLOW_KEYWORDS> token_list_t;
typedef std::array<eid_t, PER_FLOW_KEYWORDS> eid_list_t;

typedef std::array<byte, FID_SIZE> enc_fid_t;

/* state managament related */
typedef struct mgmt_buffer_flow {
    enc_fid_t     enc_fid_list[BATCH_SIZE];

    packet_t      enc_pkt_list[BATCH_SIZE];
    mac_t         mac_list[BATCH_SIZE];

    int           pkt_size_list[BATCH_SIZE];
    byte          ip_proto_list[BATCH_SIZE];
    int           init_time[BATCH_SIZE];
} mgmt_buffer_flow_t;

typedef struct enc_flow_buffer {
    byte    stream[MSS];
    mac_t   mac_list[MAX_PKT_PER_BUFFER];

    int     pkt_size_list[MAX_PKT_PER_BUFFER];
    byte    ip_proto_list[MAX_PKT_PER_BUFFER];

    int     stream_size;
    int     pkt_count;
    int     init_time;
} enc_flow_buffer_t;

typedef std::array<byte, KW_SIZE> enc_kw_t;
typedef struct enc_kw_state {
    kw_state_t kw_state;
    mac_t      mac;
} enc_kw_state_t;

#define KW_FETCH_POS 1
#define KW_FETCH_NEG 0

#endif