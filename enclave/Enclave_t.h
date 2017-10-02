#ifndef ENCLAVE_T_H__
#define ENCLAVE_T_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include "sgx_edger8r.h" /* for sgx_ocall etc. */


#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif


void ecall_init(int* log_switch, void* mgmt_buffer_flow, void* enc_flow);
void ecall_single_thread();
void ecall_producer();
void ecall_consumer();
void ecall_search_notify(const void* keyword);
void ecall_index_test_ccs(void* state_table, const void* kw_list, int count);
void ecall_index_test_our(void* state_table, const void* kw_list, int count);
void ecall_add_kw(void* state_table, const void* kw_batch, int batch_size);

sgx_status_t SGX_CDECL ocall_print_string(const char* str);
sgx_status_t SGX_CDECL ocall_get_time(int* second, int* nanosecond);
sgx_status_t SGX_CDECL ocall_print_ip(uint32_t sip, uint32_t dip, uint16_t sp, uint16_t dp, uint8_t proto);
sgx_status_t SGX_CDECL ocall_packet_capture(uint8_t** retval, void* pkt_info);
sgx_status_t SGX_CDECL ocall_store(void* hid, void* token_list, void* eid_list, void* enc_flow, int flow_size, void* mac);
sgx_status_t SGX_CDECL ocall_mgmt_flow_fetch(const void* _enc_fid);
sgx_status_t SGX_CDECL ocall_mgmt_flow_flush();
sgx_status_t SGX_CDECL ocall_mgmt_kw_fetch(const void* enc_kw_list, int kw_count, void* rlt, void* enc_kw_state_list, void* mac_list);
sgx_status_t SGX_CDECL ocall_mgmt_kw_store(const void* enc_kw_list, int kw_count, const void* enc_kw_state_list, const void* mac_list);
sgx_status_t SGX_CDECL ocall_search_get_state(const void* kw, void* state, void* mac);
sgx_status_t SGX_CDECL ocall_search_put_state(const void* kw, void* state, void* mac);
sgx_status_t SGX_CDECL ocall_flow_timeout(int crt_time);
sgx_status_t SGX_CDECL u_sgxssl_ftime(void* timeptr, uint32_t timeb_len);
sgx_status_t SGX_CDECL sgx_oc_cpuidex(int cpuinfo[4], int leaf, int subleaf);
sgx_status_t SGX_CDECL sgx_thread_wait_untrusted_event_ocall(int* retval, const void* self);
sgx_status_t SGX_CDECL sgx_thread_set_untrusted_event_ocall(int* retval, const void* waiter);
sgx_status_t SGX_CDECL sgx_thread_setwait_untrusted_events_ocall(int* retval, const void* waiter, const void* self);
sgx_status_t SGX_CDECL sgx_thread_set_multiple_untrusted_events_ocall(int* retval, const void** waiters, size_t total);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
