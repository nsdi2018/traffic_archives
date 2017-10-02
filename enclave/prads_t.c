#include "prads_t.h"

#include "sgx_trts.h" /* for sgx_ocalloc, sgx_is_outside_enclave */

#include <errno.h>
#include <string.h> /* for memcpy etc */
#include <stdlib.h> /* for malloc/free etc */

#define CHECK_REF_POINTER(ptr, siz) do {	\
	if (!(ptr) || ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define CHECK_UNIQUE_POINTER(ptr, siz) do {	\
	if ((ptr) && ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)


typedef struct ms_ecall_prads_initialize_t {
	int ms_retval;
	void* ms_global_config;
	int ms__nets;
	void* ms__network;
	void* ms__os_asset_pool;
	void* ms__serv_asset_pool;
	void* ms__asset_pool;
} ms_ecall_prads_initialize_t;


typedef struct ms_ecall_prads_cxtrackerid_t {
	uint64_t ms_retval;
} ms_ecall_prads_cxtrackerid_t;

typedef struct ms_ecall_secure_ferry_t {
	void* ms_pheader;
	void* ms_packet;
	int ms_ferry_len;
	int ms_ferry_unit;
	uint8_t* ms_ferry_mac;
	int* ms_miss_count;
	int* ms_bundle_count;
	int* ms_state_count;
} ms_ecall_secure_ferry_t;

typedef struct ms_ecall_auth_enc_t {
	int ms_retval;
	uint8_t* ms_src;
	int ms_src_len;
	uint8_t* ms_dst;
	uint8_t* ms_mac;
} ms_ecall_auth_enc_t;

typedef struct ms_ecall_sync_expiration_t {
	int ms_expired_state_count;
} ms_ecall_sync_expiration_t;

typedef struct ms_ecall_check_expiration_t {
	long int ms_wall_time;
} ms_ecall_check_expiration_t;

typedef struct ms_ocall_print_string_t {
	char* ms_str;
} ms_ocall_print_string_t;

typedef struct ms_ocall_secure_state_swap_t {
	void* ms__bundled_state;
	void* ms__bundled_id;
	int* ms_is_server;
	int ms_bundle_size;
} ms_ocall_secure_state_swap_t;

typedef struct ms_ocall_calloc_t {
	void* ms_retval;
	int ms_size;
} ms_ocall_calloc_t;

typedef struct ms_ocall_free_t {
	void* ms_ptr;
} ms_ocall_free_t;

static sgx_status_t SGX_CDECL sgx_ecall_prads_initialize(void* pms)
{
	ms_ecall_prads_initialize_t* ms = SGX_CAST(ms_ecall_prads_initialize_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	void* _tmp_global_config = ms->ms_global_config;
	void* _tmp__network = ms->ms__network;
	void* _tmp__os_asset_pool = ms->ms__os_asset_pool;
	void* _tmp__serv_asset_pool = ms->ms__serv_asset_pool;
	void* _tmp__asset_pool = ms->ms__asset_pool;

	CHECK_REF_POINTER(pms, sizeof(ms_ecall_prads_initialize_t));

	ms->ms_retval = ecall_prads_initialize(_tmp_global_config, ms->ms__nets, _tmp__network, _tmp__os_asset_pool, _tmp__serv_asset_pool, _tmp__asset_pool);


	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_prads_gameover(void* pms)
{
	sgx_status_t status = SGX_SUCCESS;
	if (pms != NULL) return SGX_ERROR_INVALID_PARAMETER;
	ecall_prads_gameover();
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_prads_cxtrackerid(void* pms)
{
	ms_ecall_prads_cxtrackerid_t* ms = SGX_CAST(ms_ecall_prads_cxtrackerid_t*, pms);
	sgx_status_t status = SGX_SUCCESS;

	CHECK_REF_POINTER(pms, sizeof(ms_ecall_prads_cxtrackerid_t));

	ms->ms_retval = ecall_prads_cxtrackerid();


	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_secure_ferry(void* pms)
{
	ms_ecall_secure_ferry_t* ms = SGX_CAST(ms_ecall_secure_ferry_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	void* _tmp_pheader = ms->ms_pheader;
	int _tmp_ferry_unit = ms->ms_ferry_unit;
	size_t _len_pheader = _tmp_ferry_unit * 24;
	void* _in_pheader = NULL;
	void* _tmp_packet = ms->ms_packet;
	size_t _len_packet = _tmp_ferry_unit * 1604;
	void* _in_packet = NULL;
	uint8_t* _tmp_ferry_mac = ms->ms_ferry_mac;
	size_t _len_ferry_mac = 16;
	uint8_t* _in_ferry_mac = NULL;
	int* _tmp_miss_count = ms->ms_miss_count;
	size_t _len_miss_count = 4;
	int* _in_miss_count = NULL;
	int* _tmp_bundle_count = ms->ms_bundle_count;
	size_t _len_bundle_count = 4;
	int* _in_bundle_count = NULL;
	int* _tmp_state_count = ms->ms_state_count;
	size_t _len_state_count = 4;
	int* _in_state_count = NULL;

	if ((size_t)_tmp_ferry_unit > (SIZE_MAX / 24)) {
		status = SGX_ERROR_INVALID_PARAMETER;
		goto err;
	}

	if ((size_t)_tmp_ferry_unit > (SIZE_MAX / 1604)) {
		status = SGX_ERROR_INVALID_PARAMETER;
		goto err;
	}

	CHECK_REF_POINTER(pms, sizeof(ms_ecall_secure_ferry_t));
	CHECK_UNIQUE_POINTER(_tmp_pheader, _len_pheader);
	CHECK_UNIQUE_POINTER(_tmp_packet, _len_packet);
	CHECK_UNIQUE_POINTER(_tmp_ferry_mac, _len_ferry_mac);
	CHECK_UNIQUE_POINTER(_tmp_miss_count, _len_miss_count);
	CHECK_UNIQUE_POINTER(_tmp_bundle_count, _len_bundle_count);
	CHECK_UNIQUE_POINTER(_tmp_state_count, _len_state_count);

	if (_tmp_pheader != NULL) {
		_in_pheader = (void*)malloc(_len_pheader);
		if (_in_pheader == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_pheader, _tmp_pheader, _len_pheader);
	}
	if (_tmp_packet != NULL) {
		_in_packet = (void*)malloc(_len_packet);
		if (_in_packet == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_packet, _tmp_packet, _len_packet);
	}
	if (_tmp_ferry_mac != NULL) {
		_in_ferry_mac = (uint8_t*)malloc(_len_ferry_mac);
		if (_in_ferry_mac == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_ferry_mac, _tmp_ferry_mac, _len_ferry_mac);
	}
	if (_tmp_miss_count != NULL) {
		if ((_in_miss_count = (int*)malloc(_len_miss_count)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_miss_count, 0, _len_miss_count);
	}
	if (_tmp_bundle_count != NULL) {
		if ((_in_bundle_count = (int*)malloc(_len_bundle_count)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_bundle_count, 0, _len_bundle_count);
	}
	if (_tmp_state_count != NULL) {
		if ((_in_state_count = (int*)malloc(_len_state_count)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_state_count, 0, _len_state_count);
	}
	ecall_secure_ferry(_in_pheader, _in_packet, ms->ms_ferry_len, _tmp_ferry_unit, _in_ferry_mac, _in_miss_count, _in_bundle_count, _in_state_count);
err:
	if (_in_pheader) free(_in_pheader);
	if (_in_packet) free(_in_packet);
	if (_in_ferry_mac) free(_in_ferry_mac);
	if (_in_miss_count) {
		memcpy(_tmp_miss_count, _in_miss_count, _len_miss_count);
		free(_in_miss_count);
	}
	if (_in_bundle_count) {
		memcpy(_tmp_bundle_count, _in_bundle_count, _len_bundle_count);
		free(_in_bundle_count);
	}
	if (_in_state_count) {
		memcpy(_tmp_state_count, _in_state_count, _len_state_count);
		free(_in_state_count);
	}

	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_auth_enc(void* pms)
{
	ms_ecall_auth_enc_t* ms = SGX_CAST(ms_ecall_auth_enc_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	uint8_t* _tmp_src = ms->ms_src;
	uint8_t* _tmp_dst = ms->ms_dst;
	uint8_t* _tmp_mac = ms->ms_mac;

	CHECK_REF_POINTER(pms, sizeof(ms_ecall_auth_enc_t));

	ms->ms_retval = ecall_auth_enc(_tmp_src, ms->ms_src_len, _tmp_dst, _tmp_mac);


	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_sync_expiration(void* pms)
{
	ms_ecall_sync_expiration_t* ms = SGX_CAST(ms_ecall_sync_expiration_t*, pms);
	sgx_status_t status = SGX_SUCCESS;

	CHECK_REF_POINTER(pms, sizeof(ms_ecall_sync_expiration_t));

	ecall_sync_expiration(ms->ms_expired_state_count);


	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_check_expiration(void* pms)
{
	ms_ecall_check_expiration_t* ms = SGX_CAST(ms_ecall_check_expiration_t*, pms);
	sgx_status_t status = SGX_SUCCESS;

	CHECK_REF_POINTER(pms, sizeof(ms_ecall_check_expiration_t));

	ecall_check_expiration(ms->ms_wall_time);


	return status;
}

SGX_EXTERNC const struct {
	size_t nr_ecall;
	struct {void* ecall_addr; uint8_t is_priv;} ecall_table[7];
} g_ecall_table = {
	7,
	{
		{(void*)(uintptr_t)sgx_ecall_prads_initialize, 0},
		{(void*)(uintptr_t)sgx_ecall_prads_gameover, 0},
		{(void*)(uintptr_t)sgx_ecall_prads_cxtrackerid, 0},
		{(void*)(uintptr_t)sgx_ecall_secure_ferry, 0},
		{(void*)(uintptr_t)sgx_ecall_auth_enc, 0},
		{(void*)(uintptr_t)sgx_ecall_sync_expiration, 0},
		{(void*)(uintptr_t)sgx_ecall_check_expiration, 0},
	}
};

SGX_EXTERNC const struct {
	size_t nr_ocall;
	uint8_t entry_table[4][7];
} g_dyn_entry_table = {
	4,
	{
		{0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, },
	}
};


sgx_status_t SGX_CDECL ocall_print_string(const char* str)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_str = str ? strlen(str) + 1 : 0;

	ms_ocall_print_string_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_print_string_t);
	void *__tmp = NULL;

	ocalloc_size += (str != NULL && sgx_is_within_enclave(str, _len_str)) ? _len_str : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_print_string_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_print_string_t));

	if (str != NULL && sgx_is_within_enclave(str, _len_str)) {
		ms->ms_str = (char*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_str);
		memcpy((void*)ms->ms_str, str, _len_str);
	} else if (str == NULL) {
		ms->ms_str = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	status = sgx_ocall(0, ms);


	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_secure_state_swap(void* _bundled_state, void* _bundled_id, int* is_server, int bundle_size)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len__bundled_state = bundle_size * 512;
	size_t _len__bundled_id = bundle_size * 16;
	size_t _len_is_server = bundle_size * 4;

	ms_ocall_secure_state_swap_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_secure_state_swap_t);
	void *__tmp = NULL;

	ocalloc_size += (_bundled_state != NULL && sgx_is_within_enclave(_bundled_state, _len__bundled_state)) ? _len__bundled_state : 0;
	ocalloc_size += (_bundled_id != NULL && sgx_is_within_enclave(_bundled_id, _len__bundled_id)) ? _len__bundled_id : 0;
	ocalloc_size += (is_server != NULL && sgx_is_within_enclave(is_server, _len_is_server)) ? _len_is_server : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_secure_state_swap_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_secure_state_swap_t));

	if (_bundled_state != NULL && sgx_is_within_enclave(_bundled_state, _len__bundled_state)) {
		ms->ms__bundled_state = (void*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len__bundled_state);
		memcpy(ms->ms__bundled_state, _bundled_state, _len__bundled_state);
	} else if (_bundled_state == NULL) {
		ms->ms__bundled_state = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	if (_bundled_id != NULL && sgx_is_within_enclave(_bundled_id, _len__bundled_id)) {
		ms->ms__bundled_id = (void*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len__bundled_id);
		memcpy(ms->ms__bundled_id, _bundled_id, _len__bundled_id);
	} else if (_bundled_id == NULL) {
		ms->ms__bundled_id = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	if (is_server != NULL && sgx_is_within_enclave(is_server, _len_is_server)) {
		ms->ms_is_server = (int*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_is_server);
		memset(ms->ms_is_server, 0, _len_is_server);
	} else if (is_server == NULL) {
		ms->ms_is_server = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_bundle_size = bundle_size;
	status = sgx_ocall(1, ms);

	if (_bundled_state) memcpy((void*)_bundled_state, ms->ms__bundled_state, _len__bundled_state);
	if (is_server) memcpy((void*)is_server, ms->ms_is_server, _len_is_server);

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_calloc(void** retval, int size)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_calloc_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_calloc_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_calloc_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_calloc_t));

	ms->ms_size = size;
	status = sgx_ocall(2, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_free(void* ptr)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_free_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_free_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_free_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_free_t));

	ms->ms_ptr = SGX_CAST(void*, ptr);
	status = sgx_ocall(3, ms);


	sgx_ocfree();
	return status;
}

