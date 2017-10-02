#include "Enclave_t.h"

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


typedef struct ms_ecall_init_t {
	int* ms_log_switch;
	void* ms_mgmt_buffer_flow;
	void* ms_enc_flow;
} ms_ecall_init_t;




typedef struct ms_ecall_search_notify_t {
	void* ms_keyword;
} ms_ecall_search_notify_t;

typedef struct ms_ecall_index_test_ccs_t {
	void* ms_state_table;
	void* ms_kw_list;
	int ms_count;
} ms_ecall_index_test_ccs_t;

typedef struct ms_ecall_index_test_our_t {
	void* ms_state_table;
	void* ms_kw_list;
	int ms_count;
} ms_ecall_index_test_our_t;

typedef struct ms_ecall_add_kw_t {
	void* ms_state_table;
	void* ms_kw_batch;
	int ms_batch_size;
} ms_ecall_add_kw_t;

typedef struct ms_ocall_print_string_t {
	char* ms_str;
} ms_ocall_print_string_t;

typedef struct ms_ocall_get_time_t {
	int* ms_second;
	int* ms_nanosecond;
} ms_ocall_get_time_t;

typedef struct ms_ocall_print_ip_t {
	uint32_t ms_sip;
	uint32_t ms_dip;
	uint16_t ms_sp;
	uint16_t ms_dp;
	uint8_t ms_proto;
} ms_ocall_print_ip_t;

typedef struct ms_ocall_packet_capture_t {
	uint8_t* ms_retval;
	void* ms_pkt_info;
} ms_ocall_packet_capture_t;

typedef struct ms_ocall_store_t {
	void* ms_hid;
	void* ms_token_list;
	void* ms_eid_list;
	void* ms_enc_flow;
	int ms_flow_size;
	void* ms_mac;
} ms_ocall_store_t;

typedef struct ms_ocall_mgmt_flow_fetch_t {
	void* ms__enc_fid;
} ms_ocall_mgmt_flow_fetch_t;


typedef struct ms_ocall_mgmt_kw_fetch_t {
	void* ms_enc_kw_list;
	int ms_kw_count;
	void* ms_rlt;
	void* ms_enc_kw_state_list;
	void* ms_mac_list;
} ms_ocall_mgmt_kw_fetch_t;

typedef struct ms_ocall_mgmt_kw_store_t {
	void* ms_enc_kw_list;
	int ms_kw_count;
	void* ms_enc_kw_state_list;
	void* ms_mac_list;
} ms_ocall_mgmt_kw_store_t;

typedef struct ms_ocall_search_get_state_t {
	void* ms_kw;
	void* ms_state;
	void* ms_mac;
} ms_ocall_search_get_state_t;

typedef struct ms_ocall_search_put_state_t {
	void* ms_kw;
	void* ms_state;
	void* ms_mac;
} ms_ocall_search_put_state_t;

typedef struct ms_ocall_flow_timeout_t {
	int ms_crt_time;
} ms_ocall_flow_timeout_t;

typedef struct ms_u_sgxssl_ftime_t {
	void* ms_timeptr;
	uint32_t ms_timeb_len;
} ms_u_sgxssl_ftime_t;

typedef struct ms_sgx_oc_cpuidex_t {
	int* ms_cpuinfo;
	int ms_leaf;
	int ms_subleaf;
} ms_sgx_oc_cpuidex_t;

typedef struct ms_sgx_thread_wait_untrusted_event_ocall_t {
	int ms_retval;
	void* ms_self;
} ms_sgx_thread_wait_untrusted_event_ocall_t;

typedef struct ms_sgx_thread_set_untrusted_event_ocall_t {
	int ms_retval;
	void* ms_waiter;
} ms_sgx_thread_set_untrusted_event_ocall_t;

typedef struct ms_sgx_thread_setwait_untrusted_events_ocall_t {
	int ms_retval;
	void* ms_waiter;
	void* ms_self;
} ms_sgx_thread_setwait_untrusted_events_ocall_t;

typedef struct ms_sgx_thread_set_multiple_untrusted_events_ocall_t {
	int ms_retval;
	void** ms_waiters;
	size_t ms_total;
} ms_sgx_thread_set_multiple_untrusted_events_ocall_t;

static sgx_status_t SGX_CDECL sgx_ecall_init(void* pms)
{
	ms_ecall_init_t* ms = SGX_CAST(ms_ecall_init_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	int* _tmp_log_switch = ms->ms_log_switch;
	void* _tmp_mgmt_buffer_flow = ms->ms_mgmt_buffer_flow;
	void* _tmp_enc_flow = ms->ms_enc_flow;

	CHECK_REF_POINTER(pms, sizeof(ms_ecall_init_t));

	ecall_init(_tmp_log_switch, _tmp_mgmt_buffer_flow, _tmp_enc_flow);


	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_single_thread(void* pms)
{
	sgx_status_t status = SGX_SUCCESS;
	if (pms != NULL) return SGX_ERROR_INVALID_PARAMETER;
	ecall_single_thread();
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_producer(void* pms)
{
	sgx_status_t status = SGX_SUCCESS;
	if (pms != NULL) return SGX_ERROR_INVALID_PARAMETER;
	ecall_producer();
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_consumer(void* pms)
{
	sgx_status_t status = SGX_SUCCESS;
	if (pms != NULL) return SGX_ERROR_INVALID_PARAMETER;
	ecall_consumer();
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_search_notify(void* pms)
{
	ms_ecall_search_notify_t* ms = SGX_CAST(ms_ecall_search_notify_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	void* _tmp_keyword = ms->ms_keyword;

	CHECK_REF_POINTER(pms, sizeof(ms_ecall_search_notify_t));

	ecall_search_notify((const void*)_tmp_keyword);


	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_index_test_ccs(void* pms)
{
	ms_ecall_index_test_ccs_t* ms = SGX_CAST(ms_ecall_index_test_ccs_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	void* _tmp_state_table = ms->ms_state_table;
	void* _tmp_kw_list = ms->ms_kw_list;

	CHECK_REF_POINTER(pms, sizeof(ms_ecall_index_test_ccs_t));

	ecall_index_test_ccs(_tmp_state_table, (const void*)_tmp_kw_list, ms->ms_count);


	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_index_test_our(void* pms)
{
	ms_ecall_index_test_our_t* ms = SGX_CAST(ms_ecall_index_test_our_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	void* _tmp_state_table = ms->ms_state_table;
	void* _tmp_kw_list = ms->ms_kw_list;

	CHECK_REF_POINTER(pms, sizeof(ms_ecall_index_test_our_t));

	ecall_index_test_our(_tmp_state_table, (const void*)_tmp_kw_list, ms->ms_count);


	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_add_kw(void* pms)
{
	ms_ecall_add_kw_t* ms = SGX_CAST(ms_ecall_add_kw_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	void* _tmp_state_table = ms->ms_state_table;
	void* _tmp_kw_batch = ms->ms_kw_batch;

	CHECK_REF_POINTER(pms, sizeof(ms_ecall_add_kw_t));

	ecall_add_kw(_tmp_state_table, (const void*)_tmp_kw_batch, ms->ms_batch_size);


	return status;
}

SGX_EXTERNC const struct {
	size_t nr_ecall;
	struct {void* ecall_addr; uint8_t is_priv;} ecall_table[8];
} g_ecall_table = {
	8,
	{
		{(void*)(uintptr_t)sgx_ecall_init, 0},
		{(void*)(uintptr_t)sgx_ecall_single_thread, 0},
		{(void*)(uintptr_t)sgx_ecall_producer, 0},
		{(void*)(uintptr_t)sgx_ecall_consumer, 0},
		{(void*)(uintptr_t)sgx_ecall_search_notify, 0},
		{(void*)(uintptr_t)sgx_ecall_index_test_ccs, 0},
		{(void*)(uintptr_t)sgx_ecall_index_test_our, 0},
		{(void*)(uintptr_t)sgx_ecall_add_kw, 0},
	}
};

SGX_EXTERNC const struct {
	size_t nr_ocall;
	uint8_t entry_table[18][8];
} g_dyn_entry_table = {
	18,
	{
		{0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, },
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

sgx_status_t SGX_CDECL ocall_get_time(int* second, int* nanosecond)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_second = 4;
	size_t _len_nanosecond = 4;

	ms_ocall_get_time_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_get_time_t);
	void *__tmp = NULL;

	ocalloc_size += (second != NULL && sgx_is_within_enclave(second, _len_second)) ? _len_second : 0;
	ocalloc_size += (nanosecond != NULL && sgx_is_within_enclave(nanosecond, _len_nanosecond)) ? _len_nanosecond : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_get_time_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_get_time_t));

	if (second != NULL && sgx_is_within_enclave(second, _len_second)) {
		ms->ms_second = (int*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_second);
		memset(ms->ms_second, 0, _len_second);
	} else if (second == NULL) {
		ms->ms_second = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	if (nanosecond != NULL && sgx_is_within_enclave(nanosecond, _len_nanosecond)) {
		ms->ms_nanosecond = (int*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_nanosecond);
		memset(ms->ms_nanosecond, 0, _len_nanosecond);
	} else if (nanosecond == NULL) {
		ms->ms_nanosecond = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	status = sgx_ocall(1, ms);

	if (second) memcpy((void*)second, ms->ms_second, _len_second);
	if (nanosecond) memcpy((void*)nanosecond, ms->ms_nanosecond, _len_nanosecond);

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_print_ip(uint32_t sip, uint32_t dip, uint16_t sp, uint16_t dp, uint8_t proto)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_print_ip_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_print_ip_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_print_ip_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_print_ip_t));

	ms->ms_sip = sip;
	ms->ms_dip = dip;
	ms->ms_sp = sp;
	ms->ms_dp = dp;
	ms->ms_proto = proto;
	status = sgx_ocall(2, ms);


	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_packet_capture(uint8_t** retval, void* pkt_info)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_pkt_info = 1000 * 12;

	ms_ocall_packet_capture_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_packet_capture_t);
	void *__tmp = NULL;

	ocalloc_size += (pkt_info != NULL && sgx_is_within_enclave(pkt_info, _len_pkt_info)) ? _len_pkt_info : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_packet_capture_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_packet_capture_t));

	if (pkt_info != NULL && sgx_is_within_enclave(pkt_info, _len_pkt_info)) {
		ms->ms_pkt_info = (void*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_pkt_info);
		memset(ms->ms_pkt_info, 0, _len_pkt_info);
	} else if (pkt_info == NULL) {
		ms->ms_pkt_info = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	status = sgx_ocall(3, ms);

	if (retval) *retval = ms->ms_retval;
	if (pkt_info) memcpy((void*)pkt_info, ms->ms_pkt_info, _len_pkt_info);

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_store(void* hid, void* token_list, void* eid_list, void* enc_flow, int flow_size, void* mac)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_hid = 16;
	size_t _len_token_list = 1600;
	size_t _len_eid_list = 1600;
	size_t _len_enc_flow = flow_size;
	size_t _len_mac = 16;

	ms_ocall_store_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_store_t);
	void *__tmp = NULL;

	ocalloc_size += (hid != NULL && sgx_is_within_enclave(hid, _len_hid)) ? _len_hid : 0;
	ocalloc_size += (token_list != NULL && sgx_is_within_enclave(token_list, _len_token_list)) ? _len_token_list : 0;
	ocalloc_size += (eid_list != NULL && sgx_is_within_enclave(eid_list, _len_eid_list)) ? _len_eid_list : 0;
	ocalloc_size += (enc_flow != NULL && sgx_is_within_enclave(enc_flow, _len_enc_flow)) ? _len_enc_flow : 0;
	ocalloc_size += (mac != NULL && sgx_is_within_enclave(mac, _len_mac)) ? _len_mac : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_store_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_store_t));

	if (hid != NULL && sgx_is_within_enclave(hid, _len_hid)) {
		ms->ms_hid = (void*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_hid);
		memcpy(ms->ms_hid, hid, _len_hid);
	} else if (hid == NULL) {
		ms->ms_hid = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	if (token_list != NULL && sgx_is_within_enclave(token_list, _len_token_list)) {
		ms->ms_token_list = (void*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_token_list);
		memcpy(ms->ms_token_list, token_list, _len_token_list);
	} else if (token_list == NULL) {
		ms->ms_token_list = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	if (eid_list != NULL && sgx_is_within_enclave(eid_list, _len_eid_list)) {
		ms->ms_eid_list = (void*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_eid_list);
		memcpy(ms->ms_eid_list, eid_list, _len_eid_list);
	} else if (eid_list == NULL) {
		ms->ms_eid_list = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	if (enc_flow != NULL && sgx_is_within_enclave(enc_flow, _len_enc_flow)) {
		ms->ms_enc_flow = (void*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_enc_flow);
		memcpy(ms->ms_enc_flow, enc_flow, _len_enc_flow);
	} else if (enc_flow == NULL) {
		ms->ms_enc_flow = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_flow_size = flow_size;
	if (mac != NULL && sgx_is_within_enclave(mac, _len_mac)) {
		ms->ms_mac = (void*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_mac);
		memcpy(ms->ms_mac, mac, _len_mac);
	} else if (mac == NULL) {
		ms->ms_mac = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	status = sgx_ocall(4, ms);


	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_mgmt_flow_fetch(const void* _enc_fid)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_mgmt_flow_fetch_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_mgmt_flow_fetch_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_mgmt_flow_fetch_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_mgmt_flow_fetch_t));

	ms->ms__enc_fid = SGX_CAST(void*, _enc_fid);
	status = sgx_ocall(5, ms);


	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_mgmt_flow_flush()
{
	sgx_status_t status = SGX_SUCCESS;
	status = sgx_ocall(6, NULL);

	return status;
}

sgx_status_t SGX_CDECL ocall_mgmt_kw_fetch(const void* enc_kw_list, int kw_count, void* rlt, void* enc_kw_state_list, void* mac_list)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_enc_kw_list = 800;
	size_t _len_rlt = 100;
	size_t _len_enc_kw_state_list = 26000;
	size_t _len_mac_list = 1600;

	ms_ocall_mgmt_kw_fetch_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_mgmt_kw_fetch_t);
	void *__tmp = NULL;

	ocalloc_size += (enc_kw_list != NULL && sgx_is_within_enclave(enc_kw_list, _len_enc_kw_list)) ? _len_enc_kw_list : 0;
	ocalloc_size += (rlt != NULL && sgx_is_within_enclave(rlt, _len_rlt)) ? _len_rlt : 0;
	ocalloc_size += (enc_kw_state_list != NULL && sgx_is_within_enclave(enc_kw_state_list, _len_enc_kw_state_list)) ? _len_enc_kw_state_list : 0;
	ocalloc_size += (mac_list != NULL && sgx_is_within_enclave(mac_list, _len_mac_list)) ? _len_mac_list : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_mgmt_kw_fetch_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_mgmt_kw_fetch_t));

	if (enc_kw_list != NULL && sgx_is_within_enclave(enc_kw_list, _len_enc_kw_list)) {
		ms->ms_enc_kw_list = (void*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_enc_kw_list);
		memcpy((void*)ms->ms_enc_kw_list, enc_kw_list, _len_enc_kw_list);
	} else if (enc_kw_list == NULL) {
		ms->ms_enc_kw_list = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_kw_count = kw_count;
	if (rlt != NULL && sgx_is_within_enclave(rlt, _len_rlt)) {
		ms->ms_rlt = (void*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_rlt);
		memset(ms->ms_rlt, 0, _len_rlt);
	} else if (rlt == NULL) {
		ms->ms_rlt = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	if (enc_kw_state_list != NULL && sgx_is_within_enclave(enc_kw_state_list, _len_enc_kw_state_list)) {
		ms->ms_enc_kw_state_list = (void*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_enc_kw_state_list);
		memset(ms->ms_enc_kw_state_list, 0, _len_enc_kw_state_list);
	} else if (enc_kw_state_list == NULL) {
		ms->ms_enc_kw_state_list = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	if (mac_list != NULL && sgx_is_within_enclave(mac_list, _len_mac_list)) {
		ms->ms_mac_list = (void*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_mac_list);
		memset(ms->ms_mac_list, 0, _len_mac_list);
	} else if (mac_list == NULL) {
		ms->ms_mac_list = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	status = sgx_ocall(7, ms);

	if (rlt) memcpy((void*)rlt, ms->ms_rlt, _len_rlt);
	if (enc_kw_state_list) memcpy((void*)enc_kw_state_list, ms->ms_enc_kw_state_list, _len_enc_kw_state_list);
	if (mac_list) memcpy((void*)mac_list, ms->ms_mac_list, _len_mac_list);

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_mgmt_kw_store(const void* enc_kw_list, int kw_count, const void* enc_kw_state_list, const void* mac_list)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_enc_kw_list = 800;
	size_t _len_enc_kw_state_list = 26000;
	size_t _len_mac_list = 1600;

	ms_ocall_mgmt_kw_store_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_mgmt_kw_store_t);
	void *__tmp = NULL;

	ocalloc_size += (enc_kw_list != NULL && sgx_is_within_enclave(enc_kw_list, _len_enc_kw_list)) ? _len_enc_kw_list : 0;
	ocalloc_size += (enc_kw_state_list != NULL && sgx_is_within_enclave(enc_kw_state_list, _len_enc_kw_state_list)) ? _len_enc_kw_state_list : 0;
	ocalloc_size += (mac_list != NULL && sgx_is_within_enclave(mac_list, _len_mac_list)) ? _len_mac_list : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_mgmt_kw_store_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_mgmt_kw_store_t));

	if (enc_kw_list != NULL && sgx_is_within_enclave(enc_kw_list, _len_enc_kw_list)) {
		ms->ms_enc_kw_list = (void*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_enc_kw_list);
		memcpy((void*)ms->ms_enc_kw_list, enc_kw_list, _len_enc_kw_list);
	} else if (enc_kw_list == NULL) {
		ms->ms_enc_kw_list = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_kw_count = kw_count;
	if (enc_kw_state_list != NULL && sgx_is_within_enclave(enc_kw_state_list, _len_enc_kw_state_list)) {
		ms->ms_enc_kw_state_list = (void*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_enc_kw_state_list);
		memcpy((void*)ms->ms_enc_kw_state_list, enc_kw_state_list, _len_enc_kw_state_list);
	} else if (enc_kw_state_list == NULL) {
		ms->ms_enc_kw_state_list = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	if (mac_list != NULL && sgx_is_within_enclave(mac_list, _len_mac_list)) {
		ms->ms_mac_list = (void*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_mac_list);
		memcpy((void*)ms->ms_mac_list, mac_list, _len_mac_list);
	} else if (mac_list == NULL) {
		ms->ms_mac_list = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	status = sgx_ocall(8, ms);


	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_search_get_state(const void* kw, void* state, void* mac)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_state = 260;
	size_t _len_mac = 16;

	ms_ocall_search_get_state_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_search_get_state_t);
	void *__tmp = NULL;

	ocalloc_size += (state != NULL && sgx_is_within_enclave(state, _len_state)) ? _len_state : 0;
	ocalloc_size += (mac != NULL && sgx_is_within_enclave(mac, _len_mac)) ? _len_mac : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_search_get_state_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_search_get_state_t));

	ms->ms_kw = SGX_CAST(void*, kw);
	if (state != NULL && sgx_is_within_enclave(state, _len_state)) {
		ms->ms_state = (void*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_state);
		memset(ms->ms_state, 0, _len_state);
	} else if (state == NULL) {
		ms->ms_state = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	if (mac != NULL && sgx_is_within_enclave(mac, _len_mac)) {
		ms->ms_mac = (void*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_mac);
		memset(ms->ms_mac, 0, _len_mac);
	} else if (mac == NULL) {
		ms->ms_mac = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	status = sgx_ocall(9, ms);

	if (state) memcpy((void*)state, ms->ms_state, _len_state);
	if (mac) memcpy((void*)mac, ms->ms_mac, _len_mac);

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_search_put_state(const void* kw, void* state, void* mac)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_state = 260;
	size_t _len_mac = 16;

	ms_ocall_search_put_state_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_search_put_state_t);
	void *__tmp = NULL;

	ocalloc_size += (state != NULL && sgx_is_within_enclave(state, _len_state)) ? _len_state : 0;
	ocalloc_size += (mac != NULL && sgx_is_within_enclave(mac, _len_mac)) ? _len_mac : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_search_put_state_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_search_put_state_t));

	ms->ms_kw = SGX_CAST(void*, kw);
	if (state != NULL && sgx_is_within_enclave(state, _len_state)) {
		ms->ms_state = (void*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_state);
		memcpy(ms->ms_state, state, _len_state);
	} else if (state == NULL) {
		ms->ms_state = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	if (mac != NULL && sgx_is_within_enclave(mac, _len_mac)) {
		ms->ms_mac = (void*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_mac);
		memcpy(ms->ms_mac, mac, _len_mac);
	} else if (mac == NULL) {
		ms->ms_mac = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	status = sgx_ocall(10, ms);


	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_flow_timeout(int crt_time)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_flow_timeout_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_flow_timeout_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_flow_timeout_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_flow_timeout_t));

	ms->ms_crt_time = crt_time;
	status = sgx_ocall(11, ms);


	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_sgxssl_ftime(void* timeptr, uint32_t timeb_len)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_timeptr = timeb_len;

	ms_u_sgxssl_ftime_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_sgxssl_ftime_t);
	void *__tmp = NULL;

	ocalloc_size += (timeptr != NULL && sgx_is_within_enclave(timeptr, _len_timeptr)) ? _len_timeptr : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_sgxssl_ftime_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_sgxssl_ftime_t));

	if (timeptr != NULL && sgx_is_within_enclave(timeptr, _len_timeptr)) {
		ms->ms_timeptr = (void*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_timeptr);
		memset(ms->ms_timeptr, 0, _len_timeptr);
	} else if (timeptr == NULL) {
		ms->ms_timeptr = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_timeb_len = timeb_len;
	status = sgx_ocall(12, ms);

	if (timeptr) memcpy((void*)timeptr, ms->ms_timeptr, _len_timeptr);

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_oc_cpuidex(int cpuinfo[4], int leaf, int subleaf)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_cpuinfo = 4 * sizeof(*cpuinfo);

	ms_sgx_oc_cpuidex_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_oc_cpuidex_t);
	void *__tmp = NULL;

	ocalloc_size += (cpuinfo != NULL && sgx_is_within_enclave(cpuinfo, _len_cpuinfo)) ? _len_cpuinfo : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_oc_cpuidex_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_oc_cpuidex_t));

	if (cpuinfo != NULL && sgx_is_within_enclave(cpuinfo, _len_cpuinfo)) {
		ms->ms_cpuinfo = (int*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_cpuinfo);
		memcpy(ms->ms_cpuinfo, cpuinfo, _len_cpuinfo);
	} else if (cpuinfo == NULL) {
		ms->ms_cpuinfo = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_leaf = leaf;
	ms->ms_subleaf = subleaf;
	status = sgx_ocall(13, ms);

	if (cpuinfo) memcpy((void*)cpuinfo, ms->ms_cpuinfo, _len_cpuinfo);

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_wait_untrusted_event_ocall(int* retval, const void* self)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_sgx_thread_wait_untrusted_event_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_wait_untrusted_event_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_wait_untrusted_event_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_wait_untrusted_event_ocall_t));

	ms->ms_self = SGX_CAST(void*, self);
	status = sgx_ocall(14, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_set_untrusted_event_ocall(int* retval, const void* waiter)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_sgx_thread_set_untrusted_event_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_set_untrusted_event_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_set_untrusted_event_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_set_untrusted_event_ocall_t));

	ms->ms_waiter = SGX_CAST(void*, waiter);
	status = sgx_ocall(15, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_setwait_untrusted_events_ocall(int* retval, const void* waiter, const void* self)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_sgx_thread_setwait_untrusted_events_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_setwait_untrusted_events_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_setwait_untrusted_events_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_setwait_untrusted_events_ocall_t));

	ms->ms_waiter = SGX_CAST(void*, waiter);
	ms->ms_self = SGX_CAST(void*, self);
	status = sgx_ocall(16, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_set_multiple_untrusted_events_ocall(int* retval, const void** waiters, size_t total)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_waiters = total * sizeof(*waiters);

	ms_sgx_thread_set_multiple_untrusted_events_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_set_multiple_untrusted_events_ocall_t);
	void *__tmp = NULL;

	ocalloc_size += (waiters != NULL && sgx_is_within_enclave(waiters, _len_waiters)) ? _len_waiters : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_set_multiple_untrusted_events_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_set_multiple_untrusted_events_ocall_t));

	if (waiters != NULL && sgx_is_within_enclave(waiters, _len_waiters)) {
		ms->ms_waiters = (void**)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_waiters);
		memcpy((void*)ms->ms_waiters, waiters, _len_waiters);
	} else if (waiters == NULL) {
		ms->ms_waiters = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_total = total;
	status = sgx_ocall(17, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

