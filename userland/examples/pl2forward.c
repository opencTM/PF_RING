#define _GNU_SOURCE

#include <signal.h>
#include <sched.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/prctl.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <errno.h>
#include <poll.h>
#include <sys/time.h>
#include <time.h>
#include <sys/socket.h>
#include <netinet/ether.h>
#include <arpa/inet.h>

#include "pheader.h"
#include "pfring.h"
#include "pfutils.c"
#include "libproc.h"

#define MAX_PKT_LEN	1536
#define MAX_FILTER_LEN	1024


static struct SELF {
	char name[16];

	struct CHLD {
		pid_t pid_1;
		pid_t pid_2;
		int32_t status_1;
		int32_t status_2;
	} child;

	struct SIG {
		u_int8_t term;
	} sign;

	char *dev_1;
	char *dev_2;
	char *bpf_file;
	pfring *rx_ring;
	pfring *tx_ring;
	pfring *lo_ring;

	int rx_ifindex;
	int tx_ifindex;
	int lo_ifindex;
	u_int32_t sent_pps;
	u_int16_t watermark;
	u_int8_t to_local;
	u_int8_t debug;
	u_int8_t verbose;
	u_int8_t reflector;
	u_int8_t filter_type;
	u_int8_t use_pfring_send;
} self = {{0}, {-1, -1, -1, -1}, {0},
	NULL, NULL, NULL, NULL, NULL, NULL,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};


void __inline ipv4_int_tuple(const u_int32_t ipint, u_int8_t ipv4[])
{
	/* int -> tuple int */
	ipv4[0] = (ipint >> 24) & 0xff;
	ipv4[1] = (ipint >> 16) & 0xff;
	ipv4[2] = (ipint >> 8) & 0xff;
	ipv4[3] = ipint & 0xff;
	return;
}

u_int32_t __inline ipv4_tuple_int(const u_int8_t ipv4[])
{
	/* tuple int -> int */
	return ((ipv4[3] & 0xff) |
		((ipv4[2] << 8) & 0xff00) |
		((ipv4[1] << 16) & 0xff0000) |
		((ipv4[0] << 24) & 0xff000000));
}

u_int32_t __inline ipv4_string_int(const char *ipv4)
{
	/* string -> int */
	struct in_addr addr;
	inet_pton(AF_INET, ipv4, &addr); /* _pton support ipv4 and ipv6 */
	return ntohl(addr.s_addr);
}

void __inline mac_int_string(const u_int8_t mint[], u_char mac[])
{
	int i;
	for (i = 0; i < ETH_LEN; i++) { mac[i] = (char) mint[i]; }
	return;
}

static u_int32_t chksum(const u_char *buffer, const u_int nbytes, u_int32_t sum)
{
	int i;

	for (i = 0; i < (nbytes & ~1U); i += 2) {
		sum += (u_int16_t) ntohs(*((u_int16_t *)(buffer + i)));
		if (sum > 0xFFFF) { sum -= 0xFFFF; }
	}

	if (i < nbytes) {
		sum += buffer[i] << 8;
		if (sum > 0xFFFF) { sum -= 0xFFFF; }
	}

	return sum;
}

static u_int32_t wrapsum(u_int32_t sum)
{
	sum = ~sum & 0xFFFF;
	return htons(sum);
}

static u_char *gen_udp_packet(const u_char smac[],
			      const u_char dmac[],
			      const u_int32_t sip,
			      const u_int32_t dip,
			      const u_int16_t sport,
			      const u_int16_t dport,
			      u_int16_t pktlen)
{
	ticks tick = 0;
	char *packet = NULL;
	char *payload = NULL;
	IP_HEADER *ip = NULL;
	UDP_HEADER *udp = NULL;
	ETH_HEADER *eth = NULL;
	const size_t hdrlen = sizeof(ETH_HEADER) + sizeof(IP_HEADER) + sizeof(UDP_HEADER);

	if (pktlen < hdrlen) { pktlen = 60; }
	packet = (char *) malloc(pktlen);
	bzero(packet, pktlen);

	/* MAC */
	eth = (ETH_HEADER *) &packet[0];
	if (dmac) { bcopy(dmac, eth->dmac, ETH_LEN); }
	if (smac) { bcopy(smac, eth->smac, ETH_LEN); }

	/* TYPE IP(0800) */
	//eth->type = TYPE_IP; /* ERROR FOR LITTLE */
	packet[12] = 0x08;
	packet[13] = 0x00;

	/* IP */
	ip = (IP_HEADER *) &packet[sizeof(ETH_HEADER)];
	ip->hdrlen = 5;
	ip->version = 4;
	ip->tos = 0;
	ip->pktlen = htons(pktlen - sizeof(ETH_HEADER));
	ip->id = htons(sport);
	ip->ttl = 64;
	ip->offset = htons(0);
	ip->protocol = IPPROTO_UDP;
	ip->dip = htonl(dip);
	ip->sip = htonl(sip);
	ip->chksum = wrapsum(chksum((u_char *) ip, sizeof(IP_HEADER), 0));

	/* UDP */
	udp = (UDP_HEADER *) (packet + sizeof(ETH_HEADER) + sizeof(IP_HEADER));
	udp->sport = htons(sport);
	udp->dport = htons(dport);
	udp->hdrlen = htons(pktlen - sizeof(ETH_HEADER) - sizeof(IP_HEADER));
	udp->chksum = 0; /* 0 will auto compute the checksum */

	/* set tick */
	payload = packet + hdrlen;
	tick = getticks();
	bcopy(&tick, payload, sizeof(tick));
	return (u_char *) packet;
}

static void help_print(const char *name)
{
	printf("%s - L2Forward		Traffic from device using vanilla PF_RING\n\n", name);
	printf("-h              	[Print help]\n");
	printf("-d			[Print debug]\n");
	printf("-v              	[Verbose]\n");
	printf("-b			[Filter is black, default: white]\n");
	printf("-r			[Reflector all incoming packets to another device]\n");
	printf("-p              	[Use pfring_send() instead of pfring_send_last_packet()]\n");
	printf("-t			[Packet to local]\n");
	printf("-i <device>     	[First device name]\n");
	printf("-j <device>     	[Second device name]\n");
	printf("-x <core_id>    	[Bind -i <device> to a core]\n");
	printf("-y <core_id>    	[Bind -j <device> to a core]\n");
	printf("-w <watermark>		[Wating incoming mark]\n");
	printf("-f <filter_file>	[Filter filename]\n");
	return;
}

static void info_print(void)
{
	pfring_card_settings setting;
	pfring_get_card_settings(self.rx_ring, &setting);

	printf("[%s] pfring_get_mtu_size: %d\n", self.name, pfring_get_mtu_size(self.rx_ring));
	printf("[%s] pfring_get_num_rx_channles: %d\n", self.name, pfring_get_num_rx_channels(self.rx_ring));
	printf("[%s] pfring_get_interface_speed: %dM\n", self.name, pfring_get_interface_speed(self.rx_ring));
	printf("[%s] pfring_get_card_setting: [max_pkt_size] %d [rx_ring_slots] %d [tx_ring_slots] %d\n",
	       self.name, setting.max_packet_size, setting.rx_ring_slots, setting.tx_ring_slots);

	return;
}

static void parse_print(const u_char *pkt, const struct pfring_pkthdr hdr)
{
	int i = 0;
	char packet[10240] = {0}; /* TCP MAX DATA */

	pfring_print_parsed_pkt(packet, 10240, pkt, &hdr);

	printf("[%s] %s", self.name, packet);

	for (i = 0; i < hdr.caplen; i++) {
		if (i % 0x10 == 0) { printf("0x%04x: ", i); }

		printf("%02x", pkt[i]);

		if ((i + 1) % 0x02 == 0) { printf(" "); }

		if ((i + 1) % 0x10 == 0) { printf("\n"); }
	}
	printf("\n\n");

	return;
}

static void header_print(const struct pfring_pkthdr hdr)
{
	u_int8_t src[4];
	u_int8_t dst[4];

	ipv4_int_tuple(hdr.extended_hdr.parsed_pkt.ip_src.v4, src);
	ipv4_int_tuple(hdr.extended_hdr.parsed_pkt.ip_dst.v4, dst);

	printf("[%s] [LEN] %d [TYPE] %04x [PROTO] %02x [VLAN] %02d [SMAC] %02x:%02x:%02x:%02x:%02x:%02x [SRC] %u.%u.%u.%u:%u -> [DMAC] %02x:%02x:%02x:%02x:%02x:%02x [DST] %u.%u.%u.%u:%u\n", self.name, hdr.caplen,
	       hdr.extended_hdr.parsed_pkt.eth_type,
	       hdr.extended_hdr.parsed_pkt.l3_proto,
	       hdr.extended_hdr.parsed_pkt.vlan_id,
	       hdr.extended_hdr.parsed_pkt.smac[0],
	       hdr.extended_hdr.parsed_pkt.smac[1],
	       hdr.extended_hdr.parsed_pkt.smac[2],
	       hdr.extended_hdr.parsed_pkt.smac[3],
	       hdr.extended_hdr.parsed_pkt.smac[4],
	       hdr.extended_hdr.parsed_pkt.smac[5],
	       src[0], src[1], src[2], src[3],
	       hdr.extended_hdr.parsed_pkt.l4_src_port,
	       hdr.extended_hdr.parsed_pkt.dmac[0],
	       hdr.extended_hdr.parsed_pkt.dmac[1],
	       hdr.extended_hdr.parsed_pkt.dmac[2],
	       hdr.extended_hdr.parsed_pkt.dmac[3],
	       hdr.extended_hdr.parsed_pkt.dmac[4],
	       hdr.extended_hdr.parsed_pkt.dmac[5],
	       dst[0], dst[1], dst[2], dst[3],
	       hdr.extended_hdr.parsed_pkt.l4_dst_port);

	return;
}

static void gtp_print(const struct pfring_pkthdr hdr)
{
	u_int8_t gtp_src[4];
	u_int8_t gtp_dst[4];

	ipv4_int_tuple(hdr.extended_hdr.parsed_pkt.tunnel.tunneled_ip_src.v4, gtp_src);
	ipv4_int_tuple(hdr.extended_hdr.parsed_pkt.tunnel.tunneled_ip_dst.v4, gtp_dst);

	printf("[%s] [GTP_ID] %08x [GTP_PROTO] %02x [GTP_SRC] %u.%u.%u.%u:%u -> [GTP_DST] %u.%u.%u.%u:%u\n",
	       self.name,
	       hdr.extended_hdr.parsed_pkt.tunnel.tunnel_id,
	       hdr.extended_hdr.parsed_pkt.tunnel.tunneled_proto,
	       gtp_src[0], gtp_src[1], gtp_src[2], gtp_src[3],
	       hdr.extended_hdr.parsed_pkt.tunnel.tunneled_l4_src_port,
	       gtp_dst[0], gtp_dst[1], gtp_dst[2], gtp_dst[3],
	       hdr.extended_hdr.parsed_pkt.tunnel.tunneled_l4_dst_port);

	return;
}

static u_char *new_pkt_to_local(struct pfring_pkthdr hdr) {
	u_char *packet = NULL;
	u_char smac[ETH_LEN] = {0};
	u_char dmac[ETH_LEN] = {0};
	struct ether_addr *eth = NULL;
	const u_int8_t lo[4] = {127, 0, 0, 1};
	const char *addr = "00:00:00:00:00:00";

	/* change packet IP and MAC */
	eth = ether_aton(addr);
	bcopy(eth->ether_addr_octet, hdr.extended_hdr.parsed_pkt.dmac, ETH_LEN);
	hdr.extended_hdr.parsed_pkt.ip_dst.v4 = ipv4_tuple_int(lo);

	/* mac rebuild */
	mac_int_string(hdr.extended_hdr.parsed_pkt.smac, smac);
	mac_int_string(hdr.extended_hdr.parsed_pkt.dmac, dmac);

	/* generate new packet */
	packet = gen_udp_packet(smac, dmac,
				hdr.extended_hdr.parsed_pkt.ip_src.v4,
				hdr.extended_hdr.parsed_pkt.ip_dst.v4,
				hdr.extended_hdr.parsed_pkt.l4_src_port,
				hdr.extended_hdr.parsed_pkt.l4_dst_port,
				60);
	parse_print(packet, hdr);
	return packet;
}

static void payload_search(const struct pfring_pkthdr hdr)
{
	if (pfring_search_payload(self.rx_ring, "\x08\x06") == 0) { /* FIXME: I do not known how to use payload */
		printf("[%s] pfring_search_payload(0806) find: ARP!\n", self.name);
	} else if (hdr.extended_hdr.parsed_pkt.eth_type == TYPE_ARP) { /* so, I will use packet header to check */
		printf("[%s] pfring search eth_type(0806) find: ARP!\n", self.name);
	}
	return;
}

static int sync_collect(const pid_t pid)
{
	int status;
	if (waitpid(pid, &status, 0) > 0) {
		if (WIFEXITED(status)) { /* proc exit */
			return WEXITSTATUS(status);
		}
	}
	return -1;
}

static int async_collect(const pid_t pid)
{
	int status;
	if (waitpid(pid, &status, WNOHANG) > 0) { /* async */
		if (WIFEXITED(status)) { /* proc exit */
			return WEXITSTATUS(status);
		}
	}
	return -1;
}

static void signal_alarm(const int signum)
{
	char num[32] = {0};
	pfring_format_numbers((double) self.sent_pps, num, sizeof(num), 0);
	printf("[%s] %s pps\n", self.name, num);
	self.sent_pps = 0;
	alarm(1);
	signal(SIGALRM, signal_alarm);
	return;
}

static void signal_term(const int signum)
{
	if (!self.sign.term) {
		self.sign.term = 1;
		if (self.rx_ring) { pfring_breakloop(self.rx_ring); /* blocking recv loop */ }
		printf("[%s] interrupt in: %d\n", self.name, signum);
	}
	return;
}

static void signal_init()
{
	signal(SIGCHLD,	SIG_DFL);
	signal(SIGHUP,	signal_term);	/*  ctrl + d */
	signal(SIGTSTP,	signal_term);	/*  ctrl + z */
	signal(SIGINT,	signal_term);	/*  ctrl + c */
	signal(SIGQUIT,	signal_term);	/*  ctrl + \ */
	signal(SIGTERM, signal_term);	/* terminate */
	return;
}

static char *get_bpf_filter()
{
	char *filter = NULL;

	if (self.bpf_file) {
		FILE *fp = NULL;
		char line[MAX_FILTER_LEN] = {0};

		if (!(fp = fopen(self.bpf_file, "r"))) {
			printf("[%s] fopen('%s') filter: %s\n", self.name, self.bpf_file, strerror(errno));
			return NULL;
		}

		while (!feof(fp)) {
			bzero((void *) line, MAX_FILTER_LEN);
			fgets(line, MAX_FILTER_LEN, fp);

			while (line[0] && (line[strlen(line) - 1] == '\r' ||
					   line[strlen(line) - 1] == '\n' ||
					   line[strlen(line) - 1] == ' ')) {
				line[strlen(line) - 1] = '\0';
			}

			if (line[0] && line[0] != '#') {
				if (!filter) {
					filter = (char *) calloc(1, strlen(line) + 8);
				} else {
					filter = (char *) realloc((void *) filter, strlen(filter) + strlen(line) + 8);
				}
				strcat(filter, "(");
				strcat(filter, line);
				strcat(filter, ")");

				if (self.filter_type) {
					strcat(filter, " and ");
				} else {
					strcat(filter, " or ");
				}
			}
		}

		if (filter && strlen(filter) > 5) { filter[strlen(filter) - 5] = '\0'; }

		if (fp) { fclose(fp); fp = NULL; }
	}

	return filter;
}

static int set_bpf_filter(pfring *bpf_ring)
{
	char *filter = NULL;

	if ((filter = get_bpf_filter())) {
		pfring_remove_bpf_filter(bpf_ring); /* remove before set */

		int rc = pfring_set_bpf_filter(bpf_ring, filter);
		printf("[%s] pfring_set_bpf_filter('%s'): %s\n", self.name, filter, rc == 0 ? "succeed" : "failed");

		free(filter);
		return rc;
	}

	return 0;
}

static void *check_filter_by_thread(void *bpf_ring)
{
	char *old = NULL;
	char *new = NULL;

	old = get_bpf_filter();

	while (1) {
		new = get_bpf_filter();

		if (new && old && strcmp(old, new) != 0) {
			set_bpf_filter((pfring *) bpf_ring);
			old = realloc(old, strlen(new) + 1);
			bzero(old, strlen(new) + 1);
			strcpy(old, new);
		} else if (new && old) { /* filter has no change */
			usleep(1000 * 10);
		} else if (new) { /* first filter is new */
			set_bpf_filter((pfring *) bpf_ring);
			old = calloc(1, strlen(new) + 1);
			strcpy(old, new);
		} else if (old) { /* first filter is old */
			set_bpf_filter((pfring *) bpf_ring);
		} else { /* has no bpf file */
			usleep(1000 * 100);
		}

		if (new) { free(new); new = NULL; }
	}

	if (old) { free(old); old = NULL; }

	return NULL;
}

static int create_rx_ring(char *dev_rx)
{
	/* create rx ring */
	if (!(self.rx_ring = pfring_open(dev_rx, MAX_PKT_LEN,
					 PF_RING_PROMISC |
					 PF_RING_CHUNK_MODE |
					 PF_RING_LONG_HEADER |
					 //PF_RING_DO_NOT_PARSE |
					 //PF_RING_ZC_SYMMETRIC_RSS |
					 //PF_RING_ZC_FIXED_RSS_Q_0 |
					 (self.use_pfring_send ? 0 : PF_RING_RX_PACKET_BOUNCE)))) {
		printf("[%s] pfring_open('%s'): %s\n", self.name, dev_rx, strerror(errno));
		return 1;
	}

	if (pfring_bind(self.rx_ring, dev_rx) != 0) {
		printf("[%s] pfring_bind('%s'): %s\n", self.name, dev_rx, strerror(errno));
		return 1;
	}

	pfring_set_application_name(self.rx_ring, "pl2forward-rx");
	pfring_set_direction(self.rx_ring, rx_only_direction);	/* only recv */
	pfring_set_socket_mode(self.rx_ring, recv_only_mode);	/* recv packet from socket */
	pfring_set_poll_watermark(self.rx_ring, self.watermark);/* until watermark num incoming packet arrived */
	pfring_set_packet_slicing(self.rx_ring, L4_SLICING, 0); /* parse L4 */
	pfring_enable_rss_rehash(self.rx_ring);			/* enable rss hash */
	pfring_get_bound_device_ifindex(self.rx_ring, &self.rx_ifindex);

	return 0;
}

static int create_tx_ring(char *dev_tx)
{
	/* create tx ring */
	if (!(self.tx_ring = pfring_open(dev_tx, MAX_PKT_LEN,
					 PF_RING_PROMISC |
					 PF_RING_CHUNK_MODE |
					 //PF_RING_DO_NOT_PARSE |
					 //PF_RING_ZC_FIXED_RSS_Q_0 |
					 //PF_RING_ZC_SYMMETRIC_RSS |
					 PF_RING_LONG_HEADER))) {
		printf("[%s] pfring_open('%s'): %s\n", self.name, dev_tx, strerror(errno));
		return 1;
	}

	pfring_set_application_name(self.tx_ring, "pl2forward-tx");
	pfring_set_socket_mode(self.tx_ring, send_only_mode);	/* only send */
	pfring_set_tx_watermark(self.tx_ring, 0);		/* send immediate */
	pfring_get_bound_device_ifindex(self.tx_ring, &self.tx_ifindex);

	return 0;
}

static int create_lo_ring()
{
	/* create lo ring */
	if (!(self.lo_ring = pfring_open("lo", MAX_PKT_LEN,
					 PF_RING_PROMISC |
					 PF_RING_CHUNK_MODE |
					 PF_RING_DO_NOT_PARSE |
					 //PF_RING_ZC_FIXED_RSS_Q_0 |
					 //PF_RING_ZC_SYMMETRIC_RSS |
					 PF_RING_LONG_HEADER))) {
		printf("[%s] pfring_open('lo'): %s\n", self.name, strerror(errno));
		return 1;
	}

	pfring_set_application_name(self.lo_ring, "pl2forward-lo");
	pfring_set_socket_mode(self.lo_ring, send_only_mode);
	pfring_set_tx_watermark(self.lo_ring, 0);
	pfring_get_bound_device_ifindex(self.lo_ring, &self.lo_ifindex);

	return 0;
}

static int enable_ring(void)
{
	/* enable socket */
	if (pfring_enable_ring(self.rx_ring) != 0) {
		printf("[%s] unable enable rx_ring\n", self.name);
		return 1;
	}

	if (self.use_pfring_send) {
		if (pfring_enable_ring(self.tx_ring)) {
			printf("[%s] unable enable tx_ring\n", self.name);
			return 1;
		}
		if (pfring_enable_ring(self.lo_ring)) {
			printf("[%s] unable enable lo_ring\n", self.name);
			return 1;
		}
	} else {
		pfring_close(self.tx_ring);
		pfring_close(self.lo_ring);
		self.tx_ring = NULL;
		self.lo_ring = NULL;
	}

	return 0;
}

static int l2_forward(char *dev_rx, char *dev_tx, const int bind_core)
{
	int ret = -1;
	PROC *p = NULL;

	if ((ret = create_rx_ring(dev_rx)) != 0) { goto L2_FORWARD_DONE; }

	if ((ret = create_tx_ring(dev_tx)) != 0) { goto L2_FORWARD_DONE; }

	if ((ret = create_lo_ring()) != 0) { goto L2_FORWARD_DONE; }

	if ((ret = enable_ring()) != 0) { goto L2_FORWARD_DONE; }

	pfring_set_promisc(self.rx_ring, 0); /* TODO: set receive ring no promisc??? */

	if (bind_core >= 0) { bind2core(bind_core); }

	if (self.bpf_file) { if ((p = proc_init())) { proc_start(p, check_filter_by_thread, (void *) self.rx_ring); } }

	if (self.debug > 0) { info_print(); }

	usleep(1000 * 100);
	signal(SIGALRM, signal_alarm);
	alarm(1);

	if (self.reflector) { /* use reflector mode */
		pfring_set_reflector_device(self.rx_ring, dev_tx); /* packet direct reflector to output device */

		pause();

		if (self.sign.term) {
			ret = 0;
			printf("[%s] break by interrupt!\n", self.name);
			goto L2_FORWARD_DONE;
		}
	}

	while (1) {
		u_char *pkt;
		struct pfring_pkthdr hdr;

		if (pfring_recv(self.rx_ring, &pkt, 0, &hdr, 1) > 0) {
			int rc;

			if (self.debug > 0) { header_print(hdr); }

			if (self.debug > 1) { parse_print(pkt, hdr); }

			if (self.debug > 2) { gtp_print(hdr); }

			if (self.debug > 3) {
				void *chunk;
				pfring_chunk_info chunk_info;
				payload_search(hdr);
				printf("[%s] [trunk] %d\n", self.name, pfring_recv_chunk(self.rx_ring, &chunk, &chunk_info, 1));
			}

			if (self.use_pfring_send) { /* pfring_send support vlan, must enable LRO, GRO, TSO */
				if (self.to_local && hdr.extended_hdr.parsed_pkt.eth_type == TYPE_IP) {
					u_char *new = new_pkt_to_local(hdr);
					rc = pfring_send(self.lo_ring, (char *) new, 60, 1); /* send new packet to lo */
					free(new);
				} else {
					rc = pfring_send(self.tx_ring, (char *) pkt, hdr.caplen, 1);
				}

				if (rc < 0) {
					printf("[%s] pfring_send(caplen=%u <= l2+mtu(%u)?): %d\n",
					       self.name, hdr.caplen, self.tx_ring->mtu, rc);
				} else if (self.verbose) {
					printf("[%s] %d bytes packet\n", self.name, hdr.len);
				}
			} else { /* pfring_send_last_rx_packet could not support vlan */
				rc = pfring_send_last_rx_packet(self.rx_ring, self.tx_ifindex);
				if (rc < 0) {
					printf("[%s] pfring_send_last_rx_packet(): %d\n", self.name, rc);
				} else if (self.verbose) {
					printf("[%s] %d bytes packet\n", self.name, hdr.len);
				}
			}

			if (rc >= 0) { self.sent_pps++; }
		}

		if (self.sign.term) {
			ret = 0;
			printf("[%s] break by interrupt!\n", self.name);
			break;
		}
	}

L2_FORWARD_DONE:

	if (p) { proc_stop(p, 1); proc_delete(&p); }

	if (self.rx_ring) { pfring_set_promisc(self.rx_ring, 0); pfring_close(self.rx_ring); self.rx_ring = NULL; }
#if 1
	if (self.tx_ring) { pfring_set_promisc(self.tx_ring, 0); pfring_close(self.tx_ring); self.tx_ring = NULL; }
	if (self.lo_ring) { pfring_set_promisc(self.lo_ring, 0); pfring_close(self.lo_ring); self.lo_ring = NULL; }
#else
	if (self.use_pfring_send) {
		pfring_close(self.tx_ring);
		pfring_close(self.lo_ring);
		self.tx_ring = NULL;
		self.lo_ring = NULL;
	}
#endif
	return ret;
}

int main(int argc, char *argv[], char **envp)
{
	char c = (char) 0;
	int bind_core_1 = -1;
	int bind_core_2 = -1;

	while ((c = getopt(argc, argv, "hi:j:x:y:f:bprvdtw:")) != -1) {
		switch (c) {
		case 'h':
			help_print(argv[0]);
			return 0;
			break;
		case 'i':
			self.dev_1 = strdup(optarg);
			break;
		case 'j':
			self.dev_2 = strdup(optarg);
			break;
		case 'x':
			bind_core_1 = atoi(optarg);
			break;
		case 'y':
			bind_core_2 = atoi(optarg);
			break;
		case 'f':
			self.bpf_file = strdup(optarg);
			break;
		case 'b':
			self.filter_type = 1; /* black */
			break;
		case 'p':
			self.use_pfring_send = 1;
			break;
		case 'r':
			self.reflector = 1;
			break;
		case 'v':
			self.verbose = 1;
			break;
		case 'd':
			self.debug += 1;
			break;
		case 't':
			self.to_local = 1;
			break;
		case 'w':
			self.watermark = atoi(optarg);
			break;
		}
	}

	if ((!self.dev_1) || (!self.dev_2)) {
		printf("You must specify two devices!\n");
		return -1;
	}

	if(strcmp(self.dev_1, self.dev_2) == 0) {
		printf("[%s] devices must be different!\n", argv[0]);
		return -1;
	}

	signal_init();
	snprintf(self.name, sizeof(self.name), "pforward-master");
	if (prctl(PR_SET_NAME, self.name, 0, 0, 0) == -1) { return 1; }
	if (prctl(PR_SET_PDEATHSIG, 15, 0, 0, 0) == -1) { return 1; }

	if ((self.child.pid_1 = fork()) == 0) { /* bond core 1 rx -> tx */
		signal_init();
		snprintf(self.name, sizeof(self.name), "pforward-%s", self.dev_1);
		if (prctl(PR_SET_NAME, self.name, 0, 0, 0) == -1) { return 1; }
		if (prctl(PR_SET_PDEATHSIG, 15, 0, 0, 0) == -1) { return 1; }
		exit(l2_forward(self.dev_1, self.dev_2, bind_core_1));
	}

	if ((self.child.pid_2 = fork()) == 0) { /* bond core 2 tx -> rx */
		signal_init();
		snprintf(self.name, sizeof(self.name), "pforward-%s", self.dev_2);
		if (prctl(PR_SET_NAME, self.name, 0, 0, 0) == -1) { return 1; }
		if (prctl(PR_SET_PDEATHSIG, 15, 0, 0, 0) == -1) { return 1; }
		exit(l2_forward(self.dev_2, self.dev_1, bind_core_2));
	}

	if (self.child.pid_1 < 0 || self.child.pid_2 < 0) { /* fork error */
		if (self.child.pid_1 > 0) { kill(self.child.pid_1, SIGTERM); sync_collect(self.child.pid_1); }
		if (self.child.pid_2 > 0) { kill(self.child.pid_2, SIGTERM); sync_collect(self.child.pid_2); }
	} else {
		pause();

		sleep(1); /* wait child exit */

		if (self.child.pid_1 > 0) {
			if ((self.child.status_1 = async_collect(self.child.pid_1)) != 0) {
				kill(self.child.pid_1, SIGTERM);
				self.child.status_1 = sync_collect(self.child.pid_1);
			}
		}

		if (self.child.pid_2 > 0) {
			if ((self.child.status_2 = async_collect(self.child.pid_2)) != 0) {
				kill(self.child.pid_2, SIGTERM);
				self.child.status_2 = sync_collect(self.child.pid_2);
			}
		}
	}

	printf("[%s] %s -> %s exit status: %d\n", self.name, self.dev_1, self.dev_2, self.child.status_1);
	printf("[%s] %s -> %s exit status: %d\n", self.name, self.dev_2, self.dev_1, self.child.status_2);

	if (self.dev_1) { pfring_set_if_promisc(self.dev_1, 0); free(self.dev_1); self.dev_1 = NULL; }
	if (self.dev_2) { pfring_set_if_promisc(self.dev_2, 0); free(self.dev_2); self.dev_2 = NULL; }

	if (self.bpf_file) { free(self.bpf_file); self.bpf_file = NULL; }

	return (self.child.status_1 & self.child.status_2);
}
