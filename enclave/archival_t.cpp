#include "sgx_trts.h"
#include "sgx_tcrypto.h"
#include "sgx_thread.h"

#include "crypto.h"
#include "Enclave_t.h"
#include "enclave_utils.h"
#include "../common/data_type.h"

#include <unordered_map>

byte K_0[KEY_LEN] = { 0 };
byte K_r[KEY_LEN] = { 0 };

#if STATE_MGMT==0
std::unordered_map<std::string, flow_buffer_t> flow_buffer;

std::unordered_map<fid_t, flow_state_t> flow_state;

std::unordered_map<std::string, kw_state_t> kw_state;
#else
std::unordered_map<fid_t, flow_state_t> flow_state;

byte K_fid[KEY_LEN] = { 0 };
byte K_pkt[KEY_LEN] = { 0 };
byte K_kw[KEY_LEN] = { 0 };

mgmt_buffer_flow_t *mgmt_buffer_flow;
enc_flow_buffer_t *enc_flow;
#endif

std::list<ready_flow_t> ready_flow_queue;

/* Synchroinization Primitives */
#if MULTI_THREAD==1
sgx_thread_mutex_t ready_queue_mutex = SGX_THREAD_MUTEX_INITIALIZER;
sgx_thread_cond_t ready_queue_cond_empty = SGX_THREAD_COND_INITIALIZER;
sgx_thread_cond_t ready_queue_cond_full = SGX_THREAD_COND_INITIALIZER;

sgx_thread_mutex_t kw_state_mutex = SGX_THREAD_MUTEX_INITIALIZER;
#endif

int *log_switch;
void ecall_init(int *_log_switch, void *_mgmt_buffer_flow, void *_enc_flow)
{
    log_switch = _log_switch;

#if STATE_MGMT==0
    flow_buffer.reserve(1000);
    kw_state.reserve(1000000);
#endif
    flow_state.reserve(1000);

    draw_rand(K_0, KEY_LEN);
    draw_rand(K_r, KEY_LEN);

#if STATE_MGMT==1
    draw_rand(K_fid, KEY_LEN);
    draw_rand(K_pkt, KEY_LEN);
    draw_rand(K_kw, KEY_LEN);

    mgmt_buffer_flow = (mgmt_buffer_flow_t *)_mgmt_buffer_flow;
    enc_flow = (enc_flow_buffer_t *)_enc_flow;
#endif
    /*tdp_init();

    rand_t r_0;
    draw_rand(&r_0, sizeof(rand_t));

    rand_t r_temp = r_0, r_n;
    int n = 1000;
    
    for (int i = 0; i < n; ++i) {
        tdp_pri(&r_temp, sizeof(rand_t), &r_n);
        r_temp = r_n;
    }

    rand_t _r_0 = r_n;
    for (int i = 0; i < n; ++i) {
        tdp_pub(&r_temp, sizeof(rand_t), &_r_0);
        r_temp = _r_0;
    }

    print("%d %d\n", n, memcmp(&r_0, &_r_0, 128));
    abort();*/
}

void get_flow_id(packet_t &packet, fid_t &fid)
{
    memcpy(&fid[0], &packet[12], 4);
    memcpy(&fid[4], &packet[16], 4);
    memcpy(&fid[12], &packet[9], 1);
    memcpy(&fid[8], &packet[TRANS_OFFSET - IP_OFFSET], 2);
    memcpy(&fid[10], &packet[TRANS_OFFSET - IP_OFFSET + 2], 2);

    /*uint32_t sip, dip;
    uint16_t sp, dp;
    uint8_t proto;
    memcpy(&sip, &packet[12], 4);
    memcpy(&dip, &packet[16], 4);
    memcpy(&sp, &packet[TRANS_OFFSET - IP_OFFSET], 2);
    memcpy(&dp, &packet[TRANS_OFFSET - IP_OFFSET + 2], 2);
    memcpy(&proto, &packet[9], 1);
    
    ocall_print_ip(sip, dip, sp, dp, proto);*/
}

int flow_indexing_encryption_storing();

#if STATE_MGMT==1
void mgmt_flow_recover_partial(enc_flow_buffer_t *enc_flow, flow_buffer_t *dec_flow)
{
    int pkt_count = enc_flow->pkt_count;
    int *pkt_size_list = enc_flow->pkt_size_list;
    mac_t *mac = enc_flow->mac_list;

    byte *enc_flow_ptr = dec_flow->stream;
    byte *dec_flow_ptr = dec_flow->stream;

    for (int i = 0; i < pkt_count; ++i) {
        /* decrypt packets */
        veri_dec(K_pkt, KEY_LEN, enc_flow_ptr, pkt_size_list[i], dec_flow_ptr, &mac[i]);
        enc_flow_ptr += pkt_size_list[i];
        dec_flow_ptr += pkt_size_list[i];

        /* copy other fields */
        dec_flow->pkt_size_list[i] = enc_flow->pkt_size_list[i];
        dec_flow->ip_proto_list[i] = enc_flow->ip_proto_list[i];
    }
}
#endif

#if STATE_MGMT == 0
int packet_capture_flow_classification()
{
    static batch_t input_batch;
    uint8_t *captured;

    /** packet capture **/
    ocall_packet_capture(&captured, &input_batch.info_list);
    memcpy(&input_batch.packet_list, captured, BATCH_SIZE*MAX_PACKET_LEN);

    /** flow classification **/
    // TODO handle explicit connection termination flag RST/FIN
    for (int i = 0; i < BATCH_SIZE; ++i) {
        packet_t &pkt = input_batch.packet_list[i];
        pinfo& pkt_info = input_batch.info_list[i];

        fid_t fid(FID_SIZE, 0);
        get_flow_id(pkt, fid); // line 1

        flow_state_t& state = flow_state[fid];

        flow_buffer_t& flow = flow_buffer[fid];

        /* fresh flow
        * create new entry (indeed done above)
        */
        if (state.flow_size == 0) {
            flow.pkt_size_list[0] = pkt_info.pkt_len;
            flow.ip_proto_list[0] = pkt_info.ip_proto;
            memcpy(&flow.stream[state.flow_size], &pkt, pkt_info.pkt_len);
            state.pkt_count = 1;
            state.flow_size = pkt_info.pkt_len;
            state.init_time = pkt_info.timestamp;
        }
        /* incomplete flow
        * add full packet to buffer
        */
        else if ((state.flow_size + pkt_info.pkt_len) < MSS) {
            flow.pkt_size_list[state.pkt_count] = pkt_info.pkt_len;
            flow.ip_proto_list[state.pkt_count] = pkt_info.ip_proto;
            memcpy(&flow.stream[state.flow_size], &pkt, pkt_info.pkt_len);
            ++state.pkt_count;
            state.flow_size += pkt_info.pkt_len;
        }
        /* flow to be completed
        * add partial packet to fill the buffer
        */
        else if (state.flow_size < MSS) {
            flow.pkt_size_list[state.pkt_count] = MSS - state.flow_size;
            flow.ip_proto_list[state.pkt_count] = pkt_info.ip_proto;
            memcpy(&flow.stream[state.flow_size], &pkt, MSS - state.flow_size);
            ++state.pkt_count;
            state.flow_size = MSS;

            static int ccc = 0;
#if MULTI_THREAD==0
            ready_flow_queue.push_back(std::make_tuple(fid, state, flow));
            flow_indexing_encryption_storing();
#else
            while (sgx_thread_mutex_trylock(&ready_queue_mutex) != 0)
                ;

            if (ready_flow_queue.size() == READY_QUEUE_CAP)
                // mutex is re-acquired after wake-up
                sgx_thread_cond_wait(&ready_queue_cond_full, &ready_queue_mutex);

            // ready_flow_queue.size() < READY_QUEUE_CAP holds
            ready_flow_queue.push_back(std::make_tuple(fid, state, flow));

            if (ready_flow_queue.size() == 500)
                sgx_thread_cond_signal(&ready_queue_cond_empty);

            //print("[*] %d %d %d %d\n", ready_flow_queue.size(), flow_buffer.size(), flow_state.size(), kw_state.size());
            sgx_thread_mutex_unlock(&ready_queue_mutex);
#endif
            if ((ccc++ % 5000) == 0)
                print("[*] ready: %d flow: %d kw: %d\n", ready_flow_queue.size(), flow_state.size(), kw_state.size());

            /*if (ccc > 20000)
                return 1;*/
            flow_state.erase(fid);
            flow_buffer.erase(fid);
        }
        /* completed flow */
        else {
            // since we have flushed the buffers of completed flow,
            // this will never happen
            print("[*] Oops? What's wrong with you? %d\n", state.flow_size);
            abort();
        }
    }

    /*if (kw_state.size() >= LOG_THRESHOLD)
        *log_switch = 1;*/
    /*if (*log_switch == 0 && 
        flow_buffer.size() >= LOG_THRESHOLD &&
        kw_state.size() >= 980000) {
        print("Log upon %d flows\n", flow_buffer.size());
        *log_switch = 1;
        return 1;
    }*/
    if (kw_state.size() > 200000 && flow_buffer.size() > 40000)
    {
        print("Memory at flow: %d kw: %d\n", flow_buffer.size(), kw_state.size());
        return 1;
    }

    if (flow_state.size() >= 200000) {
        int crt_time_s, crt_time_ns;
        ocall_get_time(&crt_time_s, &crt_time_ns);

        //print("before flow timeout checking %d\n", flow_state.size());
        auto state_it = flow_state.begin();
        auto buf_it = flow_buffer.begin();
        for (;
            state_it != flow_state.end();) {
            if ((crt_time_s - state_it->second.init_time) >= FLOW_TIMEOUT) {
                state_it = flow_state.erase(state_it);
                buf_it = flow_buffer.erase(buf_it);
            }
            else {
                ++state_it;
                ++buf_it;
            }
        }
        //print("after flow timeout checking %d\n", flow_state.size());
    }

    return 0;
}
#else
int packet_capture_flow_classification()
{
    //static batch_t input_batch;
    static packet_t in_packet_list[BATCH_SIZE];
    static pinfo_t in_info_list[BATCH_SIZE];
    uint8_t *captured;

    // per-batch flow distribution
    static std::unordered_map<fid_t, std::list<int>> flow_dist;

    /** packet capture **/
    ocall_packet_capture(&captured, &in_info_list);
    memcpy(&in_packet_list, captured, BATCH_SIZE*MAX_PACKET_LEN);

    //return 0;
    /** flow classification **/
    for (int i = 0; i < BATCH_SIZE; ++i) {
        packet_t &pkt = in_packet_list[i];
        pinfo& pkt_info = in_info_list[i];

        fid_t fid(FID_SIZE, 0);
        get_flow_id(pkt, fid);

        // record flow distribution
        flow_dist[fid].push_back(i);

        // TODO: debug enc/dec, now use plaintext fid as the performance impact is little
        //enc(K_fid, KEY_LEN, &fid, FID_SIZE, &mgmt_buffer_flow->enc_fid_list[i]);
        memcpy(&mgmt_buffer_flow->enc_fid_list[i], fid.data(), FID_SIZE);

        flow_state_t& state = flow_state[fid];

        // check RST and FIN flag
        if (pkt_info.ip_proto == IP_PROTO_TCP &&
            (pkt[33] & 0x5) != 0) {
            //print("termination %x!\n", pkt[13]);
            goto flow_ready;
        }

        /* fresh flow 
         * create new entry (indeed done above)
         */
        if (state.flow_size == 0) {
            mgmt_buffer_flow->pkt_size_list[i] = pkt_info.pkt_len;
            mgmt_buffer_flow->ip_proto_list[i] = pkt_info.ip_proto;
            mgmt_buffer_flow->init_time[i] = pkt_info.timestamp;
            auth_enc(K_pkt, KEY_LEN, &pkt, pkt_info.pkt_len, 
                    &mgmt_buffer_flow->enc_pkt_list[i], 
                    &mgmt_buffer_flow->mac_list[i]);

            state.pkt_count = 1;
            state.flow_size = pkt_info.pkt_len;
            state.init_time = pkt_info.timestamp;
        }
        /* incomplete flow 
         * add full packet to buffer
         */
        else if ((state.flow_size + pkt_info.pkt_len) < MSS) {            
            mgmt_buffer_flow->pkt_size_list[i] = pkt_info.pkt_len;
            mgmt_buffer_flow->ip_proto_list[i] = pkt_info.ip_proto;
            auth_enc(K_pkt, KEY_LEN, &pkt, pkt_info.pkt_len, 
                    &mgmt_buffer_flow->enc_pkt_list[i], 
                    &mgmt_buffer_flow->mac_list[i]);

            ++state.pkt_count;
            state.flow_size += pkt_info.pkt_len;
        }
        /* flow to be completed
         * add partial packet to fill the buffer
         */
        else if (state.flow_size < MSS) {      
flow_ready:        
            // no need to flush this packet
            mgmt_buffer_flow->pkt_size_list[i] = 0;

            // try to reconstruct flow
            static flow_buffer_t flow;
            int proc_pkt_count = 0;
            int proc_stream_size = 0;

            // Check if the entire flow is contained in this very batch
            // Note that the state hasn't been udpated yet
            if (flow_dist[fid].size() < (state.pkt_count + 1)) {
                // 1) fetch the encrypted flow buffer outside enclave
                // pass pointer outside enclave... 
                ocall_mgmt_flow_fetch(mgmt_buffer_flow->enc_fid_list[i].data());
                /*if ((enc_flow->pkt_count+flow_dist[fid].size()) != state.pkt_count) {
                    print("wubba lubba %d %d %d %d %d\n", enc_flow->pkt_count, state.pkt_count,
                        enc_flow->stream_size, state.flow_size, flow_dist[fid].size());
                    abort();
                }*/

                // 2) recover fetched partial flow
                mgmt_flow_recover_partial(enc_flow, &flow);

                proc_pkt_count = enc_flow->pkt_count;
                proc_stream_size = enc_flow->stream_size;
            }
            //print("11111 %d %d\n", proc_pkt_count, proc_stream_size);
            
            std::list<int>& pkt_idx = flow_dist[fid];
            // handle in-batch packets
            if (proc_pkt_count < state.pkt_count) {
                for (auto it = pkt_idx.begin();
                    it != pkt_idx.end(); ++it) {
                    int idx = *it;

                    // remember to mark corresponding packet in managament buffer
                    mgmt_buffer_flow->pkt_size_list[idx] = 0;

                    flow.ip_proto_list[proc_pkt_count] = in_info_list[idx].ip_proto;
                    flow.pkt_size_list[proc_pkt_count] = in_info_list[idx].pkt_len;
                    memcpy(&flow.stream[proc_stream_size], &in_packet_list[idx], in_info_list[idx].pkt_len);

                    proc_stream_size += in_info_list[idx].pkt_len;
                    ++proc_pkt_count;

                    // skip the very current one
                    if (proc_pkt_count == state.pkt_count)
                        break;
                }
            }
            //print("22222 %d %d %d\n", state.pkt_count, proc_pkt_count, proc_stream_size);
            // handle the very current packet
            flow.ip_proto_list[proc_pkt_count] = pkt_info.ip_proto;
            int space_left = MSS - proc_stream_size;
            flow.pkt_size_list[proc_pkt_count] = std::min(space_left, pkt_info.pkt_len);
            //print("1 left %d last %d crt %d total %d\n", space_left, flow.pkt_size_list[proc_pkt_count], proc_stream_size, proc_stream_size+ flow.pkt_size_list[proc_pkt_count]);
            memcpy(&flow.stream[proc_stream_size], &pkt, flow.pkt_size_list[proc_pkt_count]);
            //print("2 left %d last %d crt %d total %d\n", space_left, flow.pkt_size_list[proc_pkt_count], proc_stream_size, proc_stream_size + flow.pkt_size_list[proc_pkt_count]);

            // udpate flow state
            state.pkt_count = proc_pkt_count + 1;
            state.flow_size = proc_stream_size + flow.pkt_size_list[proc_pkt_count];

            // reset flow distribution after use
            pkt_idx.clear();
            //print("33333 %d %d left %d last %d\n", proc_pkt_count, proc_stream_size, 
            //    space_left, flow.pkt_size_list[proc_pkt_count]);

#if MULTI_THREAD==0
            ready_flow_queue.push_back(std::make_tuple(fid, state, flow));
            flow_indexing_encryption_storing();
#else
            while(sgx_thread_mutex_trylock(&ready_queue_mutex) != 0)
                ;

            if (ready_flow_queue.size() == READY_QUEUE_CAP)
                // mutex is re-acquired after wake-up
                sgx_thread_cond_wait(&ready_queue_cond_full, &ready_queue_mutex);

            // ready_flow_queue.size() < READY_QUEUE_CAP holds
            ready_flow_queue.push_back(std::make_tuple(fid, state, flow));

            if (ready_flow_queue.size() == 1) {
                //print("yoyo!\n");
                sgx_thread_cond_signal(&ready_queue_cond_empty);
            }

            //print("[*] %d %d %d %d\n", ready_flow_queue.size(), flow_buffer.size(), flow_state.size(), kw_state.size());
            sgx_thread_mutex_unlock(&ready_queue_mutex);
#endif
            flow_state.erase(fid);
        }
        /* completed flow */
        else {
            // since we have flushed the buffers of completed flow,
            // this will never happen
            print("[*] Oops? What's wrong with you? %d\n", state.flow_size);
            //abort();
        }
    }

    // flush flow state management buffer
    /*char bb[1500];
    print("==============Start\n");
    for (int i = 0; i < BATCH_SIZE; ++i) {
        if (mgmt_buffer_flow->pkt_size_list[i] == 0)
            continue;
        if (veri_dec(K_pkt, KEY_LEN,
            &mgmt_buffer_flow->enc_pkt_list[i],
            mgmt_buffer_flow->pkt_size_list[i],
            bb, &mgmt_buffer_flow->mac_list[i]) == 0) {
            print("cccccc!\n");
            abort();
        }
    }
    print("==============end\n");*/
    ocall_mgmt_flow_flush();

    // reset flow distribution
    flow_dist.clear();

    /*if (*log_switch == 1)
        return 1;*/

    /* flow timeout checking */
    if (flow_state.size() >= 200000) {
        int crt_time_s, crt_time_ns;
        ocall_get_time(&crt_time_s, &crt_time_ns);

        print("before flow timeout checking %d\n", flow_state.size());
        for (auto it = flow_state.begin();
            it != flow_state.end();) {
            if ((crt_time_s - it->second.init_time) >= FLOW_TIMEOUT) {
                it = flow_state.erase(it);
            }
            else {
                ++it;
            }
        }
        print("after flow timeout checking %d\n", flow_state.size());

        ocall_flow_timeout(crt_time_s);
    }

    return 0;
}
#endif

int keyword_extraction(const fid_t& fid, const flow_buffer_t& flow, int pkt_count,
                       keyword_t kw_list[])
{
    int kw_count = 0;

    // 5-tuple as keyword
    memcpy(&kw_list[0], fid.data(), 4);
    memcpy(&kw_list[1], fid.data() + 4, 4);
    memcpy(&kw_list[2], fid.data() + 8, 2);
    memcpy(&kw_list[3], fid.data() + 10, 2);
    memcpy(&kw_list[4], fid.data() + 12, 1);
    kw_count = 5;

    // TODO: proper tokenization
    static const std::string delim = " ,:;.?!-\t\n\r=\'\"";
    // currently use string API for ease of implementation
    std::string pkt_str(MAX_PACKET_LEN, 0);
    int processed_size = 0;
    for (int i = 0; i < pkt_count; ++i) {
        int pkt_payload_offset = (flow.ip_proto_list[i] == IP_PROTO_TCP ? TCP_PAYLOAD_OFFSET : UDP_PAYLOAD_OFFSET);
        if (flow.pkt_size_list[i] < pkt_payload_offset) {
            processed_size += flow.pkt_size_list[i];
            continue;
        }

        // we are only interested in the "payload of each packet"
        pkt_str.assign(&flow.stream[processed_size+pkt_payload_offset], flow.pkt_size_list[i]);
        processed_size += flow.pkt_size_list[i];

        size_t delim_pos = pkt_str.find_first_of(delim);
        size_t word_pos = 0;
        while (delim_pos != std::string::npos) {
            int kw_size = delim_pos - word_pos;
            //if (kw_size > 1) { // in case of continous punctuations
            if(kw_size == KW_SIZE){ // only interested in keyword of exactly 8 byte
                //kw_list[kw_count++].assign(pkt_str.data() + word_pos, kw_size > KW_SIZE ? KW_SIZE : kw_size);
                memcpy(&kw_list[kw_count++], 
                       pkt_str.data() + word_pos,
                       kw_size > KW_SIZE ? KW_SIZE : kw_size);                

                // expected number of keywords extracted, return
                if (kw_count == PER_FLOW_KEYWORDS)
                    return kw_count;
            }
            word_pos = delim_pos + 1;
            delim_pos = pkt_str.find_first_of(delim, word_pos);
        }
        // ignore last word, if any
    }

    return kw_count;
}

inline void byte_or(const byte *ina, const byte *inb,
    int len, byte *out) {
    for (int i = 0; i < len; ++i)
        out[i] = ina[i] ^ inb[i];
}

int flow_indexing_encryption_storing()
{
    ready_flow_t ready_flow;

#if MULTI_THREAD==0
    memcpy(&ready_flow, &ready_flow_queue.front(), sizeof(ready_flow_t));
    ready_flow_queue.pop_front();
#else
    while (sgx_thread_mutex_trylock(&ready_queue_mutex) != 0)
        ;

    if (ready_flow_queue.empty())
        // mutex is re-acquired after wake-up
        sgx_thread_cond_wait(&ready_queue_cond_empty, &ready_queue_mutex);

    // !ready_flow_queue.empty() holds
    memcpy(&ready_flow, &ready_flow_queue.front(), sizeof(ready_flow_t));
    ready_flow_queue.pop_front();

    if (ready_flow_queue.size() == 1000){//READY_QUEUE_CAP - 1) {
        //print("hgaha!\n");
        sgx_thread_cond_signal(&ready_queue_cond_full);
    }

    sgx_thread_mutex_unlock(&ready_queue_mutex);
#endif

    fid_t &fid = std::get<0>(ready_flow);
    flow_state_t &state = std::get<1>(ready_flow);
    flow_buffer_t &flow = std::get<2>(ready_flow);

    /** flow indexing **/
    /* Keyword Extraction */
    keyword_t kw_list[PER_FLOW_KEYWORDS];
    int kw_count = keyword_extraction(fid, flow, state.pkt_count, kw_list);

    // TODO: debug
    // quick fix
    if (kw_count == 0)
        return 0;

#if STATE_MGMT==0
    kw_state_t kw_state_list[PER_FLOW_KEYWORDS];
    for (int i = 0; i < kw_count; ++i)
        kw_state_list[i] = kw_state[KW_TO_STR(kw_list[i])];
#else
    byte       rlt[PER_FLOW_KEYWORDS];
    kw_state_t kw_state_list[PER_FLOW_KEYWORDS];
    mac_t      kw_mac_list[PER_FLOW_KEYWORDS];
    ocall_mgmt_kw_fetch(&kw_list, kw_count, &rlt, &kw_state_list, &kw_mac_list);
    for (int i = 0; i < kw_count; ++i) {
        if(rlt[i] == KW_FETCH_POS)
            veri_dec(K_kw, KEY_LEN, &kw_state_list[i], sizeof(kw_state_t),
                &kw_state_list[i], &kw_mac_list[i]);
    }
#endif

    /* Index Entry Generation */
    hid_t hid;
    hash(&fid, FID_SIZE, &hid); // Alg2: line 1

    token_list_t token_list;
    eid_list_t eid_list;

    byte K_w[KEY_LEN];
    byte K_hid[KEY_LEN];

    for (int i = 0; i < kw_count; ++i) {
        keyword_t& kw = kw_list[i];
        kw_state_t &state = kw_state_list[i];

        prf(K_0, kw.data(), kw.size(), K_w);    // Alg2: line 4
        
        // fresh keyword
        if (state.counter == 0) {               // Alg2: line 5-9
            draw_rand(&(state.rand[0]), RAND_LEN);
            // TODO: encrypt rand with K_r and send to server 
        }
        // existing keyword
        else {
#if CCS16 == 1
            rand_t new_r = state.rand;
            tdp_pri(&new_r, RAND_LEN, &state.rand);
#endif
        }

        prf(K_w, &state, sizeof(kw_state_t), &token_list[i][0]);  // Alg2: line 12                                                           
        
        prf(K_w, &state, sizeof(kw_state_t), K_hid);               // Alg2: line 13
        byte_or((byte *)&hid, K_hid, 16, &eid_list[i][0]);

        ++state.counter;                                                 // Alg2: line 14
    }
    
#if STATE_MGMT==0
    for (int i = 0; i < kw_count; ++i)
        kw_state[KW_TO_STR(kw_list[i])] = kw_state_list[i];
#else
    for (int i = 0; i < kw_count; ++i) {
        auth_enc(K_kw, KEY_LEN, &kw_state_list[i], sizeof(kw_state_t),
            &kw_state_list[i], &kw_mac_list[i]);
    }
    ocall_mgmt_kw_store(&kw_list, kw_count, &kw_state_list, &kw_mac_list);
#endif

    /** flow encryption **/
    byte K_f[KEY_LEN];
    prf(K_0, &hid, sizeof(hid_t), K_f);
    byte enc_flow[MSS];
    mac_t mac;
    
    auth_enc(K_f, KEY_LEN, flow.stream, MSS, enc_flow, &mac);
    
    /** storing **/
    ocall_store(&hid,
                &token_list,
                &eid_list,
                enc_flow, MSS,
                &mac);

    return 0;
}

void ecall_producer()
{
    while (packet_capture_flow_classification() == 0)
        ;
}

void ecall_consumer()
{
    print("consumer in enclave %d\n");
    while (flow_indexing_encryption_storing() == 0)
        ;
}

void ecall_single_thread()
{
    while (packet_capture_flow_classification() == 0)
        ;
}

void ecall_search_notify(const void *keyword)
{
    // encrypt keyword
#if CCS16==0 && STATE_MGMT==1
    kw_state_t state;
    mac_t mac;

    ocall_search_get_state(keyword, &state, &mac);
    veri_dec(K_kw, KEY_LEN, &state, sizeof(kw_state_t), &state, &mac);

    rand_t new_r = state.rand;
    tdp_pri(&new_r, RAND_LEN, &state.rand);

    auth_enc(K_kw, KEY_LEN, &state, sizeof(kw_state_t), &state, &mac);
    ocall_search_put_state(keyword, &state, &mac);
#endif
}

void ecall_add_kw(void *_state_table,
                  const void *_kw_batch, int batch_size)
{
#if STATE_MGMT==0
    std::unordered_map<std::string, kw_state_t> &state_table = kw_state;
#else
    std::unordered_map<std::string, enc_kw_state_t> &state_table =
        *(std::unordered_map<std::string, enc_kw_state_t> *)_state_table;
#endif
    keyword_t *kw_batch = (keyword_t *)_kw_batch;
    
    static std::string kw(KW_SIZE, 0);
    for (int i = 0; i < batch_size; ++i) {
        kw.assign(&kw_batch[i][0], KW_SIZE);

#if STATE_MGMT==0
        kw_state_t &state = state_table[kw];
#else
        kw_state_t &state = state_table[kw].kw_state;
        mac_t &mac = state_table[kw].mac;
#endif
        ++state.counter;
        draw_rand(&state.rand[0], RAND_LEN);
#if STATE_MGMT==1
        auth_enc(K_kw, KEY_LEN, &state, sizeof(kw_state_t), &state, &mac);
#endif
    }
}

void ecall_index_test_ccs(void *_state_table,
                          const void *_kw_list, int count)
{
    std::unordered_map<std::string, kw_state_t> &state_table =
        *(std::unordered_map<std::string, kw_state_t> *)_state_table;
    keyword_t *kw_list = (keyword_t *)_kw_list;
    
    hid_t hid;
    draw_rand(&hid, HID_LEN);

    byte K_w[KEY_LEN];
    byte K_hid[KEY_LEN];

    token_t token;
    eid_t eid;
    rand_t new_r;

    byte temp[20] = { 0 };

    std::string kw(KW_SIZE, 0);
    for (int i = 0; i < count; ++i) {
        kw.assign(&kw_list[i][0], KW_SIZE);
        kw_state_t &state = state_table[kw];

        //print("%d: %s %d\n", i, kw.c_str(), state.counter);

        prf(K_0, kw.data(), kw.size(), K_w);    // Alg2: line 4

        // fresh keyword
        if (state.counter == 0) {               // Alg2: line 5-9
            draw_rand(&(state.rand[0]), RAND_LEN);
            // TODO: encrypt rand with K_r and send to server
            print("[*] yayayaa\n");
        }
        // existing keyword
        else {
            new_r = state.rand;
            tdp_pri(&new_r, RAND_LEN, &state.rand);
        }

        // trick
        memcpy(temp, &state, 20);
        prf(K_w, temp, 20, &token);  // Alg2: line 12                                                           
        //prf(K_w, &state, sizeof(kw_state_t), &token);  // Alg2: line 12                                                           

        //prf(K_w, &state, sizeof(kw_state_t), &K_hid);               // Alg2: line 13
        prf(K_w, temp, 20, &K_hid);  // Alg2: line 12

        byte_or(&hid[0], K_hid, HID_LEN, &eid[0]);

        ++state.counter;                                                 // Alg2: line 14
    }                                                          
}

void ecall_index_test_our(void *_state_table,
    const void *_kw_list, int count)
{
    std::unordered_map<std::string, kw_state_t> &state_table =
        *(std::unordered_map<std::string, kw_state_t> *)_state_table;
    keyword_t *kw_list = (keyword_t *)_kw_list;


    hid_t hid;
    draw_rand(&hid, HID_LEN);

    byte K_w[KEY_LEN];
    byte K_hid[KEY_LEN];

    token_t token;
    eid_t eid;

    byte temp[20] = { 0 };

    std::string kw(KW_SIZE, 0);
    for (int i = 0; i < count; ++i) {
        kw.assign((byte *)&kw_list[i], KW_SIZE);
        kw_state_t &state = state_table[kw];

        prf(K_0, kw.data(), kw.size(), K_w);    // Alg2: line 4

                                                // fresh keyword
        if (state.counter == 0) {               // Alg2: line 5-9
            draw_rand(&(state.rand[0]), RAND_LEN);
            // TODO: encrypt rand with K_r and send to server
            print("[*] yayayaa\n");
        }
        // existing keyword
        else {
        }

        memcpy(temp, &state, 20);
        prf(K_w, temp, 20, &token);  // Alg2: line 12    
        //prf(K_w, &state, sizeof(kw_state_t), &token);  // Alg2: line 12                                                           

        //prf(K_w, &state, sizeof(kw_state_t), K_hid);               // Alg2: line 13
        prf(K_w, temp, 20, &K_hid);  // Alg2: line 12

        byte_or((byte *)&hid, K_hid, 16, &eid[0]);

        ++state.counter;                                                 // Alg2: line 14
    }
}