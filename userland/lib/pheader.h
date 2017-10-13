#ifndef __P_HEADER_H__
#define __P_HEADER_H__

#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <net/ethernet.h>
#include <arpa/inet.h>

#define ETH_LEN		6	/* NIC物理地址 */
#define TYPE_IP		0x0800	/* TYPE IP */
#define TYPE_ARP	0x0806	/* TYPE ARP */
#define TYPE_RARP	0x0835	/* 逆地址解析协议 RARP */

#define TH_FIN		0x01
#define TH_SYN		0x02
#define TH_RST		0x04
#define TH_PUSH		0x08
#define TH_ACK		0x10
#define TH_URG		0x20


typedef struct __ETH_HEADER__ {
	u_char dmac[ETH_LEN];
	u_char smac[ETH_LEN];
	u_int16_t type;
} ETH_HEADER;


typedef struct __ARP_HEADER__ {
	u_int16_t hrd;
	u_int16_t pro;
	u_int8_t hlen;
	u_int8_t plen;
	u_int16_t opt;
} ARP_HEADER;


typedef struct __IP_HEADER__ {
#if BYTE_ORDER == LITTLE_ENDIAN
	u_int32_t hdrlen:4;
	u_int32_t version:4;
#else
	u_int32_t version:4;
	u_int32_t hdrlen:4;
#endif
	u_int8_t tos;
	u_int16_t pktlen;
	u_int16_t id;
	u_int16_t offset; /* fragment offset field */
	u_int8_t ttl;
	u_int8_t protocol;
	u_int16_t chksum;
	u_int32_t sip;
	u_int32_t dip;
} IP_HEADER;


typedef struct __TCP_HEADER__ {
	u_int16_t sport;
	u_int16_t dport;
	u_int32_t seq;
	u_int32_t ack;
#if LITTLE_ENDIAN
	u_int8_t resvd1:4;
	u_int8_t hdrlen:4;
	u_int8_t flag:6;
	u_int8_t resvd2:2;
#else
	u_int8_t hdrlen:4;
	u_int8_t resvd1:4;
	u_int8_t resvd2:2;
	u_int8_t flag:6;
#endif
	u_int16_t winsize;
	u_int16_t chksum;
	u_int16_t urgt_p; /* 外带数据 */
} TCP_HEADER;


typedef struct __UDP_HEADER__ {
	u_int16_t sport;
	u_int16_t dport;
	u_int16_t hdrlen;
	u_int16_t chksum;
} UDP_HEADER;


typedef struct __ETH_ARP__ {
	struct __ARP_HEADER__ arp;
	u_int8_t sha[ETH_LEN];
	u_int8_t spa[4];
	u_int8_t tha[ETH_LEN];
	u_int8_t tpa[4];
} ETH_ARP;

#define arp_hrd ea_hdr.ar_hrd
#define arp_pro ea_hdr.ar_pro
#define arp_hln ea_hdr.ar_hln
#define arp_pln ea_hdr.ar_pln
#define arp_op ea_hdr.ar_op
#define ARPHRD 1


typedef struct __TCP_IP__ {
	struct __IP_HEADER__ ip;
	struct __TCP_HEADER__ tcp;
} TCP_IP;


typedef struct __UDP_IP__ {
	struct __IP_HEADER__ ip;
	struct __UDP_HEADER__ udp;
} UDP_IP;


typedef struct __ICMP_8__ { /* icmp能到达目的地, 响应-请求包 */
	u_int8_t type;
	u_int8_t code; /* type sub code (报文类型子码) */
	u_int16_t chksum;
	u_int16_t id;
	u_int16_t seq;
	char data[1];
} ICMP_8;


typedef struct __ICMP_0__ { /* icmp能返回目的地, 响应-应答包 */
	u_int8_t type;
	u_int8_t code; /* type sub code(报文类型子码) */
	u_int16_t chksum;
	u_int16_t id;
	u_int16_t seq;
	char data[1];
} ICMP_0;


typedef struct __ICMP_3__ { /* icmp不能到达目的地 */
	u_int8_t type;
	u_int8_t code; /* type sub code(报文类型子码), 例如:0网络原因不能到达,1主机原因不能到达... */
	u_int16_t chksum;
	u_int16_t pmvoid;
	u_int16_t nextmtu;
	char data[1];
} ICMP_3;


typedef struct __ICMP_5__ { /* icmp报文(重发结构体) */
	u_int8_t type;
	u_int8_t code; /* type sub code(报文类型子码) */
	u_int16_t chksum;
	struct in_addr gwaddr;
	char data[1];
} ICMP_5;

typedef struct __ICMP_11__ {
	u_int8_t type;
	u_int8_t code; /* type sub code(报文类型子码) */
	u_int16_t chksum;
	u_int32_t icmpvoid;
	char data[1];
} ICMP_11;

#endif
