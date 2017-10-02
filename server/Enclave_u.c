#include "Enclave_u.h"
#include <errno.h>

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

static sgx_status_t SGX_CDECL Enclave_ocall_print_string(void* pms)
{
	ms_ocall_print_string_t* ms = SGX_CAST(ms_ocall_print_string_t*, pms);
	ocall_print_string((const char*)ms->ms_str);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_get_time(void* pms)
{
	ms_ocall_get_time_t* ms = SGX_CAST(ms_ocall_get_time_t*, pms);
	ocall_get_time(ms->ms_second, ms->ms_nanosecond);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_print_ip(void* pms)
{
	ms_ocall_print_ip_t* ms = SGX_CAST(ms_ocall_print_ip_t*, pms);
	ocall_print_ip(ms->ms_sip, ms->ms_dip, ms->ms_sp, ms->ms_dp, ms->ms_proto);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_packet_capture(void* pms)
{
	ms_ocall_packet_capture_t* ms = SGX_CAST(ms_ocall_packet_capture_t*, pms);
	ms->ms_retval = ocall_packet_capture(ms->ms_pkt_info);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_store(void* pms)
{
	ms_ocall_store_t* ms = SGX_CAST(ms_ocall_store_t*, pms);
	ocall_store(ms->ms_hid, ms->ms_token_list, ms->ms_eid_list, ms->ms_enc_flow, ms->ms_flow_size, ms->ms_mac);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_mgmt_flow_fetch(void* pms)
{
	ms_ocall_mgmt_flow_fetch_t* ms = SGX_CAST(ms_ocall_mgmt_flow_fetch_t*, pms);
	ocall_mgmt_flow_fetch((const void*)ms->ms__enc_fid);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_mgmt_flow_flush(void* pms)
{
	if (pms != NULL) return SGX_ERROR_INVALID_PARAMETER;
	ocall_mgmt_flow_flush();
	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_mgmt_kw_fetch(void* pms)
{
	ms_ocall_mgmt_kw_fetch_t* ms = SGX_CAST(ms_ocall_mgmt_kw_fetch_t*, pms);
	ocall_mgmt_kw_fetch((const void*)ms->ms_enc_kw_list, ms->ms_kw_count, ms->ms_rlt, ms->ms_enc_kw_state_list, ms->ms_mac_list);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_mgmt_kw_store(void* pms)
{
	ms_ocall_mgmt_kw_store_t* ms = SGX_CAST(ms_ocall_mgmt_kw_store_t*, pms);
	ocall_mgmt_kw_store((const void*)ms->ms_enc_kw_list, ms->ms_kw_count, (const void*)ms->ms_enc_kw_state_list, (const void*)ms->ms_mac_list);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_search_get_state(void* pms)
{
	ms_ocall_search_get_state_t* ms = SGX_CAST(ms_ocall_search_get_state_t*, pms);
	ocall_search_get_state((const void*)ms->ms_kw, ms->ms_state, ms->ms_mac);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_search_put_state(void* pms)
{
	ms_ocall_search_put_state_t* ms = SGX_CAST(ms_ocall_search_put_state_t*, pms);
	ocall_search_put_state((const void*)ms->ms_kw, ms->ms_state, ms->ms_mac);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_flow_timeout(void* pms)
{
	ms_ocall_flow_timeout_t* ms = SGX_CAST(ms_ocall_flow_timeout_t*, pms);
	ocall_flow_timeout(ms->ms_crt_time);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_u_sgxssl_ftime(void* pms)
{
	ms_u_sgxssl_ftime_t* ms = SGX_CAST(ms_u_sgxssl_ftime_t*, pms);
	u_sgxssl_ftime(ms->ms_timeptr, ms->ms_timeb_len);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_sgx_oc_cpuidex(void* pms)
{
	ms_sgx_oc_cpuidex_t* ms = SGX_CAST(ms_sgx_oc_cpuidex_t*, pms);
	sgx_oc_cpuidex(ms->ms_cpuinfo, ms->ms_leaf, ms->ms_subleaf);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_sgx_thread_wait_untrusted_event_ocall(void* pms)
{
	ms_sgx_thread_wait_untrusted_event_ocall_t* ms = SGX_CAST(ms_sgx_thread_wait_untrusted_event_ocall_t*, pms);
	ms->ms_retval = sgx_thread_wait_untrusted_event_ocall((const void*)ms->ms_self);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_sgx_thread_set_untrusted_event_ocall(void* pms)
{
	ms_sgx_thread_set_untrusted_event_ocall_t* ms = SGX_CAST(ms_sgx_thread_set_untrusted_event_ocall_t*, pms);
	ms->ms_retval = sgx_thread_set_untrusted_event_ocall((const void*)ms->ms_waiter);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_sgx_thread_setwait_untrusted_events_ocall(void* pms)
{
	ms_sgx_thread_setwait_untrusted_events_ocall_t* ms = SGX_CAST(ms_sgx_thread_setwait_untrusted_events_ocall_t*, pms);
	ms->ms_retval = sgx_thread_setwait_untrusted_events_ocall((const void*)ms->ms_waiter, (const void*)ms->ms_self);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_sgx_thread_set_multiple_untrusted_events_ocall(void* pms)
{
	ms_sgx_thread_set_multiple_untrusted_events_ocall_t* ms = SGX_CAST(ms_sgx_thread_set_multiple_untrusted_events_ocall_t*, pms);
	ms->ms_retval = sgx_thread_set_multiple_untrusted_events_ocall((const void**)ms->ms_waiters, ms->ms_total);

	return SGX_SUCCESS;
}

static const struct {
	size_t nr_ocall;
	void * table[18];
} ocall_table_Enclave = {
	18,
	{
		(void*)Enclave_ocall_print_string,
		(void*)Enclave_ocall_get_time,
		(void*)Enclave_ocall_print_ip,
		(void*)Enclave_ocall_packet_capture,
		(void*)Enclave_ocall_store,
		(void*)Enclave_ocall_mgmt_flow_fetch,
		(void*)Enclave_ocall_mgmt_flow_flush,
		(void*)Enclave_ocall_mgmt_kw_fetch,
		(void*)Enclave_ocall_mgmt_kw_store,
		(void*)Enclave_ocall_search_get_state,
		(void*)Enclave_ocall_search_put_state,
		(void*)Enclave_ocall_flow_timeout,
		(void*)Enclave_u_sgxssl_ftime,
		(void*)Enclave_sgx_oc_cpuidex,
		(void*)Enclave_sgx_thread_wait_untrusted_event_ocall,
		(void*)Enclave_sgx_thread_set_untrusted_event_ocall,
		(void*)Enclave_sgx_thread_setwait_untrusted_events_ocall,
		(void*)Enclave_sgx_thread_set_multiple_untrusted_events_ocall,
	}
};
sgx_status_t ecall_init(sgx_enclave_id_t eid, int* log_switch, void* mgmt_buffer_flow, void* enc_flow)
{
	sgx_status_t status;
	ms_ecall_init_t ms;
	ms.ms_log_switch = log_switch;
	ms.ms_mgmt_buffer_flow = mgmt_buffer_flow;
	ms.ms_enc_flow = enc_flow;
	status = sgx_ecall(eid, 0, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t ecall_single_thread(sgx_enclave_id_t eid)
{
	sgx_status_t status;
	status = sgx_ecall(eid, 1, &ocall_table_Enclave, NULL);
	return status;
}

sgx_status_t ecall_producer(sgx_enclave_id_t eid)
{
	sgx_status_t status;
	status = sgx_ecall(eid, 2, &ocall_table_Enclave, NULL);
	return status;
}

sgx_status_t ecall_consumer(sgx_enclave_id_t eid)
{
	sgx_status_t status;
	status = sgx_ecall(eid, 3, &ocall_table_Enclave, NULL);
	return status;
}

sgx_status_t ecall_search_notify(sgx_enclave_id_t eid, const void* keyword)
{
	sgx_status_t status;
	ms_ecall_search_notify_t ms;
	ms.ms_keyword = (void*)keyword;
	status = sgx_ecall(eid, 4, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t ecall_index_test_ccs(sgx_enclave_id_t eid, void* state_table, const void* kw_list, int count)
{
	sgx_status_t status;
	ms_ecall_index_test_ccs_t ms;
	ms.ms_state_table = state_table;
	ms.ms_kw_list = (void*)kw_list;
	ms.ms_count = count;
	status = sgx_ecall(eid, 5, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t ecall_index_test_our(sgx_enclave_id_t eid, void* state_table, const void* kw_list, int count)
{
	sgx_status_t status;
	ms_ecall_index_test_our_t ms;
	ms.ms_state_table = state_table;
	ms.ms_kw_list = (void*)kw_list;
	ms.ms_count = count;
	status = sgx_ecall(eid, 6, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t ecall_add_kw(sgx_enclave_id_t eid, void* state_table, const void* kw_batch, int batch_size)
{
	sgx_status_t status;
	ms_ecall_add_kw_t ms;
	ms.ms_state_table = state_table;
	ms.ms_kw_batch = (void*)kw_batch;
	ms.ms_batch_size = batch_size;
	status = sgx_ecall(eid, 7, &ocall_table_Enclave, &ms);
	return status;
}

