#ifndef ENCLAVE_U_H__
#define ENCLAVE_U_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include <string.h>
#include "sgx_edger8r.h" /* for sgx_satus_t etc. */


#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_print_string, (const char* str));
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_get_time, (int* second, int* nanosecond));
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_print_ip, (uint32_t sip, uint32_t dip, uint16_t sp, uint16_t dp, uint8_t proto));
uint8_t* SGX_UBRIDGE(SGX_NOCONVENTION, ocall_packet_capture, (void* pkt_info));
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_store, (void* hid, void* token_list, void* eid_list, void* enc_flow, int flow_size, void* mac));
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_mgmt_flow_fetch, (const void* _enc_fid));
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_mgmt_flow_flush, ());
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_mgmt_kw_fetch, (const void* enc_kw_list, int kw_count, void* rlt, void* enc_kw_state_list, void* mac_list));
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_mgmt_kw_store, (const void* enc_kw_list, int kw_count, const void* enc_kw_state_list, const void* mac_list));
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_search_get_state, (const void* kw, void* state, void* mac));
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_search_put_state, (const void* kw, void* state, void* mac));
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_flow_timeout, (int crt_time));
void SGX_UBRIDGE(SGX_NOCONVENTION, u_sgxssl_ftime, (void* timeptr, uint32_t timeb_len));
void SGX_UBRIDGE(SGX_CDECL, sgx_oc_cpuidex, (int cpuinfo[4], int leaf, int subleaf));
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_wait_untrusted_event_ocall, (const void* self));
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_set_untrusted_event_ocall, (const void* waiter));
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_setwait_untrusted_events_ocall, (const void* waiter, const void* self));
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_set_multiple_untrusted_events_ocall, (const void** waiters, size_t total));

sgx_status_t ecall_init(sgx_enclave_id_t eid, int* log_switch, void* mgmt_buffer_flow, void* enc_flow);
sgx_status_t ecall_single_thread(sgx_enclave_id_t eid);
sgx_status_t ecall_producer(sgx_enclave_id_t eid);
sgx_status_t ecall_consumer(sgx_enclave_id_t eid);
sgx_status_t ecall_search_notify(sgx_enclave_id_t eid, const void* keyword);
sgx_status_t ecall_index_test_ccs(sgx_enclave_id_t eid, void* state_table, const void* kw_list, int count);
sgx_status_t ecall_index_test_our(sgx_enclave_id_t eid, void* state_table, const void* kw_list, int count);
sgx_status_t ecall_add_kw(sgx_enclave_id_t eid, void* state_table, const void* kw_batch, int batch_size);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
