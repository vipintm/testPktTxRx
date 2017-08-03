/*
 * UDP IEEE 802.11 packet generator
 * This is based on https://gist.github.com/jonhoo/7780260
 * Used for packet tx->rx time measurement (from application layer to application layer)
 * - Send UDP IEEE 802.11 packet using pkt injection which include the time stamp and pkt number in data part
 * - Trigger high GPIO IO08 (40) at starting of send and go low when it is finished
 * - ??
 */
//
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <time.h>
//
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>
#include <linux/ip.h>
#include <linux/udp.h>
//
#include <mraa.h>
#include <pcap.h>
//

//debug
//#define DEBUG 1

// IEEE 802.11 Types <-- only data type required
#define WLAN_FC_TYPE_DATA	2
#define WLAN_FC_SUBTYPE_DATA	0

// Constants
#define BILLION  1000000000L // <- nano
#define nDelay  1000000 // 1000000 <- this is too much
#define IOPIN 8 // using gpio pin 40 (IO08)
#define TRGPIN 9 // using gpio pin ?? (IO09)
#define DATA_SZ 100 // Just filling data
#define STRING_SZ (DATA_SZ - 10)

/* Defined in include/linux/ieee80211.h */
struct ieee80211_hdr {
	uint16_t /*__le16*/frame_control;
	uint16_t /*__le16*/duration_id;
	uint8_t addr1[6];
	uint8_t addr2[6];
	uint8_t addr3[6];
	uint16_t /*__le16*/seq_ctrl;
//  uint8_t addr4[6];
}__attribute__ ((packed));

// TODO change to qos header, just included not used
struct ieee80211_hdr_qos {
	uint16_t /*__le16*/frame_control;
	uint16_t /*__le16*/duration_id;
	uint8_t addr1[6];
	uint8_t addr2[6];
	uint8_t addr3[6];
	uint16_t /*__le16*/seq_ctl;
//      uint8_t addr4[6];
	uint16_t /*__le16*/qc;
}__attribute__ ((packed));

// checksum
uint16_t inet_csum(const void *buf, size_t hdr_len);

// MAC address
const uint8_t mac[6] = { 0x01, 0x23, 0x45, 0x67, 0x89, 0xab };

// IP address
const char * to = "255.255.255.255";
const char * from = "169.254.1.1";

// Radiotap include/net/ieee80211_radiotap.h
static const uint8_t u8aRadiotapHeader[] = { 0x00, 0x00, 0x18, 0x00, 0x0f, 0x80,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x08, 0x00, };

// LLC header
const uint8_t ipllc[8] = { 0xaa, 0xaa, 0x03, 0x00, 0x00, 0x00, 0x08, 0x00 };

// exit vars
sig_atomic_t running = 0;
int max_packno = 100;

// Let close by CTL+C
void sig_handler(int signo) {
    if (signo == SIGINT) {
        printf("Stopping pkt tx and shutdown IO%d \n", IOPIN);
        running = -1;
    }
}

//
int main(void) {

	// VARS

	// Time measure vars
	struct timespec send_time;
	struct timespec start_time;
	struct timespec end_time;
#ifdef DEBUG
	long int diffInNanos;
	long int diffSec;
#endif

	// frame count info
	uint8_t packno = 1;

	// frame buff
	char buff[STRING_SZ];

	// Frame hdr
	uint8_t *rt; /* radiotap */
	struct ieee80211_hdr *hdr;
	uint8_t *llc;
	struct iphdr *ip;
	struct udphdr *udp;

	// frame data parts
	uint8_t *data;
	struct timespec *ntime;
	uint8_t *stime;

	/* Other useful bits */
	uint8_t *buf;
	size_t sz;
	uint8_t fcchunk[2]; /* 802.11 header frame control */
	struct sockaddr_in saddr, daddr; /* IP source and destination */

	/* PCAP vars */
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *ppcap;

	// GPIO mraa
	mraa_result_t ret = MRAA_SUCCESS;
	mraa_gpio_context gpio;
	mraa_gpio_context timePin;

	// EXEC

	// initilize GPIO LED / ext trigger
	mraa_init();
	gpio = mraa_gpio_init(IOPIN);
	if (gpio == NULL) {
		fprintf(stderr, "Error in using pin%d, NO GPIO no TEST ", IOPIN);
		exit(1);
	}

	// initilize GPIO trigger for rx board
	timePin = mraa_gpio_init(TRGPIN);
	if (timePin == NULL) {
		fprintf(stderr, "Error in using pin%d, NO GPIO no TEST ", TRGPIN);
		exit(1);
	}

	// set direction to OUT
	ret = mraa_gpio_dir(gpio, MRAA_GPIO_OUT);
	if (ret != MRAA_SUCCESS) {
		mraa_result_print(ret);
	}

	ret = mraa_gpio_dir(timePin, MRAA_GPIO_OUT);
	if (ret != MRAA_SUCCESS) {
		mraa_result_print(ret);
	}

	printf("init-ed pin%d\n", IOPIN);

	// registor signal fuc
	signal(SIGINT, sig_handler);

	// open interface mon0
	ppcap = pcap_open_live("mon0", 800, 1, 20, errbuf);

	if (ppcap == NULL) {
		fprintf(stderr,"Could not open interface mon0 for packet injection: %s",
				errbuf);
		exit(1);
	}

	printf("\n Test GPIO .... \n");
	ret = mraa_gpio_write(gpio, 0);
	if (ret != MRAA_SUCCESS) {
		mraa_result_print(ret);
	}
	sleep(1);
	ret = mraa_gpio_write(gpio, 1);
	if (ret != MRAA_SUCCESS) {
		mraa_result_print(ret);
	}
	sleep(1);

	printf("\n Let start tx .... \n");
	while (running == 0) {

		// Make sure GPIO is low
	    ret = mraa_gpio_write(gpio, 0);
	    if (ret != MRAA_SUCCESS) {
	        mraa_result_print(ret);
	    }

	    ret = mraa_gpio_write(timePin, 0);
	    if (ret != MRAA_SUCCESS) {
	        mraa_result_print(ret);
	    }

		// Total buffer size
		sz = sizeof(u8aRadiotapHeader) + sizeof(struct ieee80211_hdr)
				+ sizeof(ipllc) + sizeof(struct iphdr) + sizeof(struct udphdr)
				+ /*0*/sizeof(uint8_t) + sizeof(struct timespec) + DATA_SZ /* data */
				+ 4 /* FCS */;

		// pkt buffer
		buf = (uint8_t *) malloc(sz);

		// for string time in packet
		memset(&buff[0], 0, sizeof(buff));

		// pointers maping
		rt = (uint8_t *) buf;
		hdr = (struct ieee80211_hdr *) (rt + sizeof(u8aRadiotapHeader)); // dot11 hdr - TODO change to qos
		llc = (uint8_t *) (hdr + 1); // llc
		ip = (struct iphdr *) (llc + sizeof(ipllc)); // ip hdr
		udp = (struct udphdr *) (ip + 1); // udp hdr
		data = (uint8_t *) (udp + 1); // packet number
		ntime = (struct timespec *) (data + 1); // Epoch time
		stime = (uint8_t *) (ntime + 1); // Date and Time in string

		// The radiotap header
		memcpy(rt, u8aRadiotapHeader, sizeof(u8aRadiotapHeader));

		// 802.11 type and subtype
		fcchunk[0] = ((WLAN_FC_TYPE_DATA << 2) | (WLAN_FC_SUBTYPE_DATA << 4));
		// 802.11 From DS
		fcchunk[1] = 0x02;

		memcpy(&hdr->frame_control, &fcchunk[0], 2 * sizeof(uint8_t));

		// 802.11 NAV
		hdr->duration_id = 0xffff;

		// 802.11 mac Address
		memcpy(&hdr->addr1[0], mac, 6 * sizeof(uint8_t));
		memcpy(&hdr->addr2[0], mac, 6 * sizeof(uint8_t));
		memcpy(&hdr->addr3[0], mac, 6 * sizeof(uint8_t));

		// 802.11 seq no
		hdr->seq_ctrl = 0;

		// LLC+SNAP hdr
		memcpy(llc, ipllc, 8 * sizeof(uint8_t));

		// IP hdr type
		daddr.sin_family = AF_INET;
		saddr.sin_family = AF_INET;

		// IP ports
		daddr.sin_port = htons(50505);
		saddr.sin_port = htons(50505);

		// IP adress
		inet_pton(AF_INET, to, (struct in_addr *) &daddr.sin_addr.s_addr);
		inet_pton(AF_INET, from, (struct in_addr *) &saddr.sin_addr.s_addr);

		// IP hdr length
		ip->ihl = 5;

		// IP version
		ip->version = 4;

		// IP TOS --- TODO
		// https://www.tucny.com/Home/dscp-tos
		// http://www.cisco.com/c/en/us/products/collateral/switches/catalyst-3750-series-switches/prod_bulletin0900aecd80394844.html
		//ip->tos = 0xb8;
		ip->tos = 0x00;

		// Frag
		ip->id = 0;
		// Don't fragment
		ip->frag_off = htons(0x4000);

		// TTL
		ip->ttl = 64;

		// IP totel lenghth
		ip->tot_len = htons(
				sizeof(struct iphdr) + sizeof(struct udphdr) + DATA_SZ /* data */);

		// UDP
		ip->protocol = IPPROTO_UDP;
		ip->saddr = saddr.sin_addr.s_addr;
		ip->daddr = daddr.sin_addr.s_addr;

		// IP check sum
		ip->check = 0;
		ip->check = inet_csum(ip, sizeof(struct iphdr));

		// UDP ports
		udp->source = saddr.sin_port;
		udp->dest = daddr.sin_port;

		// UDP length
		udp->len = htons(sizeof(struct udphdr) + DATA_SZ /* data */);

		// UPD check sum
		udp->check = 0;

		// DATA packet number
		// We send max_packno + 1
		if (packno > max_packno) {
			memcpy(data, &max_packno, sizeof(uint8_t));
		} else {
			memcpy(data, &packno, sizeof(uint8_t));
		}

		// Get the epoch time
		clock_gettime(CLOCK_REALTIME, &send_time);

		// DATA epoch time
		memcpy(ntime, &send_time, sizeof(struct timespec));

		// Get the string time, just for fun
		strftime(buff, sizeof buff, "%D %T", gmtime(&send_time.tv_sec));

		//  DATA string time
		memcpy(stime, buff, STRING_SZ);

		// TODO move to 3 thread - send packet, get time, trigger gpio
		// Get start time
		clock_gettime(CLOCK_REALTIME, &start_time);

		// Trigger GPIO high
	    ret = mraa_gpio_write(timePin, 1);
	    if (ret != MRAA_SUCCESS) {
	        mraa_result_print(ret);
	    }

	    ret = mraa_gpio_write(gpio, 1);
	    if (ret != MRAA_SUCCESS) {
	        mraa_result_print(ret);
	    }

	    // Send packet
		if (pcap_sendpacket(ppcap, buf, sz) == 0) {

			// GPIO to low
		    ret = mraa_gpio_write(timePin, 0);
		    if (ret != MRAA_SUCCESS) {
		        mraa_result_print(ret);
		    }

		    ret = mraa_gpio_write(gpio, 0);
		    if (ret != MRAA_SUCCESS) {
		        mraa_result_print(ret);
		    }

			// record time
			clock_gettime(CLOCK_REALTIME, &end_time);

#ifdef DEBUG
			// calculate tx time in sec + nano sec
			if (end_time.tv_nsec >= start_time.tv_nsec
					&& end_time.tv_sec >= start_time.tv_sec) {
				diffSec = (end_time.tv_sec - start_time.tv_sec);
				diffInNanos = (end_time.tv_nsec - start_time.tv_nsec);

			} else if (start_time.tv_nsec > end_time.tv_nsec
					&& end_time.tv_sec >= start_time.tv_sec) {
				diffSec = (end_time.tv_sec - start_time.tv_sec);
				diffInNanos =
						((BILLION - start_time.tv_nsec) + end_time.tv_nsec);

			} else {
				// 1 sec ... somthing wrong
				diffSec = 1;
				diffInNanos = 0;
			}
			printf("Send a packet [%d] at %ld.%09ld sec (with %ld.%09ld sec) \n",
					packno, end_time.tv_sec, end_time.tv_nsec, diffSec,
					diffInNanos);
#else
			printf("[%d] @ %ld.%09ld \n",
					packno, end_time.tv_sec, end_time.tv_nsec);
#endif
		} else {
			pcap_perror(ppcap, "Failed to inject packet");
			running = -1;
		}

		// clean
		free(buf);

		if (nDelay)
			usleep(nDelay);

		// stop if reached max no + 1
		if (packno >= max_packno + 1) {
			running = -1;
		}

		// one more packet send
		packno++;
	}

	printf("\n Let finish ....\n");

	// close pcap
	pcap_close(ppcap);

	// make sure gpio is low
	ret = mraa_gpio_write(gpio, 0);
	if (ret != MRAA_SUCCESS) {
	    mraa_result_print(ret);
	}

	ret = mraa_gpio_write(timePin, 0);
	if (ret != MRAA_SUCCESS) {
	    mraa_result_print(ret);
	}

	// close gpio
	ret = mraa_gpio_close(gpio);
	if (ret != MRAA_SUCCESS) {
		mraa_result_print(ret);
	}

	ret = mraa_gpio_close(timePin);
	if (ret != MRAA_SUCCESS) {
		mraa_result_print(ret);
	}

	return ret;
}

// check sum
uint16_t inet_csum(const void *buf, size_t hdr_len) {
	unsigned long sum = 0;
	const uint16_t *ip1;

	ip1 = (const uint16_t *) buf;
	while (hdr_len > 1) {
		sum += *ip1++;
		if (sum & 0x80000000)
			sum = (sum & 0xFFFF) + (sum >> 16);
		hdr_len -= 2;
	}

	while (sum >> 16)
		sum = (sum & 0xFFFF) + (sum >> 16);

	return (~sum);
}
