#ifndef PRADS_T_H__
#define PRADS_T_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include "sgx_edger8r.h" /* for sgx_ocall etc. */


#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif


int ecall_prads_initialize(void* global_config, int _nets, void* _network, void* _os_asset_pool, void* _serv_asset_pool, void* _asset_pool);
void ecall_prads_gameover();
uint64_t ecall_prads_cxtrackerid();
void ecall_secure_ferry(void* pheader, void* packet, int ferry_len, int ferry_unit, uint8_t* ferry_mac, int* miss_count, int* bundle_count, int* state_count);
int ecall_auth_enc(uint8_t* src, int src_len, uint8_t* dst, uint8_t* mac);
void ecall_sync_expiration(int expired_state_count);
void ecall_check_expiration(long int wall_time);

sgx_status_t SGX_CDECL ocall_print_string(const char* str);
sgx_status_t SGX_CDECL ocall_secure_state_swap(void* _bundled_state, void* _bundled_id, int* is_server, int bundle_size);
sgx_status_t SGX_CDECL ocall_calloc(void** retval, int size);
sgx_status_t SGX_CDECL ocall_free(void* ptr);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
