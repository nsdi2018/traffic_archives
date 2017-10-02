#ifndef PRADS_U_H__
#define PRADS_U_H__

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
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_secure_state_swap, (void* _bundled_state, void* _bundled_id, int* is_server, int bundle_size));
void* SGX_UBRIDGE(SGX_NOCONVENTION, ocall_calloc, (int size));
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_free, (void* ptr));

sgx_status_t ecall_prads_initialize(sgx_enclave_id_t eid, int* retval, void* global_config, int _nets, void* _network, void* _os_asset_pool, void* _serv_asset_pool, void* _asset_pool);
sgx_status_t ecall_prads_gameover(sgx_enclave_id_t eid);
sgx_status_t ecall_prads_cxtrackerid(sgx_enclave_id_t eid, uint64_t* retval);
sgx_status_t ecall_secure_ferry(sgx_enclave_id_t eid, void* pheader, void* packet, int ferry_len, int ferry_unit, uint8_t* ferry_mac, int* miss_count, int* bundle_count, int* state_count);
sgx_status_t ecall_auth_enc(sgx_enclave_id_t eid, int* retval, uint8_t* src, int src_len, uint8_t* dst, uint8_t* mac);
sgx_status_t ecall_sync_expiration(sgx_enclave_id_t eid, int expired_state_count);
sgx_status_t ecall_check_expiration(sgx_enclave_id_t eid, long int wall_time);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
