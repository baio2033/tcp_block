#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/sysctl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <pthread.h>
#include <stdint.h>
#include <pcap.h>


#define ETHER_ADDR_LEN 6
#define ETHERNET 1
#define ETH_ARP 0x0806
#define ETHERTYPE_IP 0x0800


struct __attribute__((packed)) etherhdr {
	u_char dst[ETHER_ADDR_LEN];
	u_char src[ETHER_ADDR_LEN];
	u_int16_t ether_type; // ARP : 0x0806
};

struct __attribute__((packed)) iphdr{
    u_char  ip_v:4,         /* version */
        ip_hl:4;        /* header length */
    u_char  ip_tos;         /* type of service */
    short   ip_len;         /* total length */
    u_short ip_id;          /* identification */
    short   ip_off;         /* fragment offset field */
#define IP_DF 0x4000            /* dont fragment flag */
#define IP_MF 0x2000            /* more fragments flag */
    u_char  ip_ttl;         /* time to live */
    u_int8_t  ip_p;           /* protocol */
    u_short ip_sum;         /* checksum */
    struct  in_addr ip_src,ip_dst;  /* source and dest address */
};

struct tcp_header{
	u_int16_t tcp_src;
	u_int16_t tcp_dst;
	u_int32_t tcp_seq;
	u_int32_t tcp_ack;
	u_int8_t tcp_rev:4,tcp_off:4;
	u_int8_t tcp_flag;
	u_int16_t tcp_win;
	u_int16_t tcp_sum;
	u_int16_t tcp_ptr;
};

struct __attribute__((packed)) pseudohdr{
	struct in_addr src;
	struct in_addr dst;
	u_int8_t zero;
	u_int8_t protocol;
	u_int16_t len;	
};
