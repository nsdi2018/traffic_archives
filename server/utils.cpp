#include "Enclave_u.h"

#include <cstdio>
#include <time.h>

#include <netinet/in.h>
#include <arpa/inet.h>

void ocall_print_string(const char *str)
{
    /* Proxy/Bridge will check the length and null-terminate
    * the input string to prevent buffer overflow.
    */
    printf("%s", str);
}

void ocall_get_time(int *second, int *nanosecond)
{
    timespec wall_clock;
    clock_gettime(CLOCK_REALTIME, &wall_clock);
    *second = wall_clock.tv_sec;
    *nanosecond = wall_clock.tv_nsec;
}

void ocall_print_ip(uint32_t sip, uint32_t dip, uint16_t sp, uint16_t dp, uint8_t proto) {
    struct in_addr addr, addr2;
    addr.s_addr = sip;
    addr2.s_addr = dip;
    printf("[%s %s %u %u %u]\n", inet_ntoa(addr), inet_ntoa(addr2), ntohs(sp), ntohs(dp), proto);
}