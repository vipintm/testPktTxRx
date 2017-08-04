/*
 * UDP IEEE 802.11 packet intercepter
 * This is based on http://www.devdungeon.com/content/using-libpcap-c
 * Used for packet tx->rx time measurement (from application layer to application layer)
 * - Receive UDP IEEE 802.11 packet using pcap
 * - Take time stamp when GPIO IO7 go high ( which is mapped to tx board
 * - Trigger high GPIO IO08 (40) at starting of receive
 * - Calculate tx->rx time delay
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
#include <pcap.h>
#include <mraa.h>
//

//debug
//#define DEBUG 1

#ifdef DEBUG
// dump pkt
void pktdump(const u_char * pu8, int nLength);
#endif

// Interface
#define WLANDEV "mon0"

// Constants
#define BILLION  1000000000L // <- nano
#define MSTONANOS 1000000L
#define nDelay 0 // 1000000 <- this is too much
#define IOPIN 8 // using gpio pin 40 (IO08)
#define TRGPIN 9 // using gpio pin ?? (IO09)
#define DATA_SZ 100 // Just filling data
#define STRING_SZ (DATA_SZ - 10)

// exit vars
sig_atomic_t running = 0;
uint8_t max_packno = 100;

// pcap context
pcap_t *handle;

// GPIO context
mraa_gpio_context gpio;
mraa_gpio_context timePin;

// Let close by CTL+C
void sig_handler(int signo) {
    if (signo == SIGINT) {
        printf("Stopping pkt rx and shutdown IO%d and IO%d\n", IOPIN,TRGPIN);
        // lets stop pcap listen
        pcap_breakloop(handle);
        running = -1;
    }
}

// get time when tx interrupt is received
uint8_t tx_pktno = 0;
struct timespec tx_time;
void tx_interrupt(void* args)
{
    // Get the tx time
	clock_gettime(CLOCK_REALTIME, &tx_time);
	++tx_pktno;
}

//
int main() {

	// VARS
	// time
	struct timespec start_time;
	struct timespec end_time;
#ifdef DEBUG
	long int diffInNanos;
	long int diffInSec;
	long int delayInSec;
#endif
	long int delayInNanos;
	long float delayInMs;

	// frame count info
	uint8_t packno = 0;
	uint8_t rx_pktno = 0;

	// pcap
	const u_char *packet;
	struct pcap_pkthdr packet_header;
	char error_buffer[PCAP_ERRBUF_SIZE];
	struct bpf_program filter;
	char filter_exp[] =
			"udp && src 192.168.1.1 && dst 255.255.255.255 && src port 50505 && dst port 50505";
	bpf_u_int32 netmask=0xffffff;

#ifdef DEBUG
	// for packet dump
	int pktlength = 0;
#endif

	// pkt info
	uint8_t *pktbuf;
	uint8_t *pktnobuf;

	// GPIO mraa
	mraa_result_t ret = MRAA_SUCCESS;

	// initilize GPIO
	mraa_init();

	// pkt rx trigger
	gpio = mraa_gpio_init(IOPIN);
	if (gpio == NULL) {
		fprintf(stderr, "Error in using pin%d, NO GPIO no TEST ", IOPIN);
		exit(1);
	}

	// pkt tx trigger
	timePin = mraa_gpio_init(TRGPIN);
	if (gpio == NULL) {
		fprintf(stderr, "Error in using pin%d, NO GPIO no TEST ", TRGPIN);
		exit(1);
	}

	// set direction to OUT for pkt rx trigger
	ret = mraa_gpio_dir(gpio, MRAA_GPIO_OUT);
	if (ret != MRAA_SUCCESS) {
		mraa_result_print(ret);
		exit(1);
	}

	// set direction to OUT for pkt rx trigger
	ret = mraa_gpio_dir(timePin, MRAA_GPIO_IN);
	if (ret != MRAA_SUCCESS) {
		mraa_result_print(ret);
		exit(1);
	}

	printf("init-ed pin%d and pin%d\n", IOPIN, TRGPIN);

	// register interrupt for tx gpio
    ret = mraa_gpio_isr(timePin, MRAA_GPIO_EDGE_RISING, &tx_interrupt, NULL);
	if (ret != MRAA_SUCCESS) {
		mraa_result_print(ret);
		exit(1);
	}

	// registor signal fuc
	signal(SIGINT, sig_handler);

	// open interface mon0
	handle = pcap_open_live(WLANDEV, BUFSIZ, 1, 0, error_buffer);
	if (handle == NULL) {
		fprintf(stderr,"Could not open %s - %s\n", WLANDEV, error_buffer);
		exit(1);
	}

	// create pcap filter and apply for udp pkt with 50505
	if (pcap_compile(handle, &filter, filter_exp, 0, netmask) == -1) {
		fprintf(stderr,"Bad filter - %s\n", pcap_geterr(handle));
		exit(1);
	}
	if (pcap_setfilter(handle, &filter) == -1) {
		fprintf(stderr,"Error setting filter - %s\n", pcap_geterr(handle));
		exit(1);
	}

	// Test GPIO
	printf("\n Test GPIO .... \n");
	ret = mraa_gpio_write(gpio, 0);
	if (ret != MRAA_SUCCESS) {
		mraa_result_print(ret);
		exit(1);
	}
	sleep(1);
	ret = mraa_gpio_write(gpio, 1);
	if (ret != MRAA_SUCCESS) {
		mraa_result_print(ret);
		exit(1);
	}
	sleep(1);

	printf("\n Ready for rx .... \n");

	while (running == 0) {

		// Make sure GPIO is low
	    ret = mraa_gpio_write(gpio, 0);
	    if (ret != MRAA_SUCCESS) {
	        mraa_result_print(ret);
	    }

	    // Get the listen start time
		clock_gettime(CLOCK_REALTIME, &start_time);

		// Get the next packet
		packet = pcap_next(handle, &packet_header);
		if (packet == NULL) {
			printf("No packet found.\n");
		} else {

			// Packet receive time
			clock_gettime(CLOCK_REALTIME, &end_time);

			// Got a pkt, trigger GPIO
			ret = mraa_gpio_write(gpio, 1);
			if (ret != MRAA_SUCCESS) {
				mraa_result_print(ret);
			}

			// got a pkt
			++packno;

			// pkt number from data
			pktbuf = (uint8_t *) packet;
			pktnobuf = (uint8_t *) (pktbuf + 96); // 96 ->> magic location
			memcpy(&rx_pktno, pktnobuf, sizeof(uint8_t));

#ifdef DEBUG
			// Get pkt length
			pktlength = packet_header.len;
			printf("Lenght  of packet no tx : %d rx : %d - %d\n",
					tx_pktno, rx_pktno, pktlength);
#endif

			// TODO : extract time stamp <-- No use at this time

			if(rx_pktno != packno) {
				printf("Packet is missing tx :%d rx :%d counted pkt no :%d\n",
						tx_pktno, rx_pktno, packno);
				packno = rx_pktno;
			}

			// Calculate tx->rx time
			if(tx_pktno == rx_pktno) {
				// The packet should receive less than a second
				if (end_time.tv_nsec >= tx_time.tv_nsec
						&& end_time.tv_sec == tx_time.tv_sec) {
					delayInNanos = (end_time.tv_nsec - tx_time.tv_nsec);
					delayInMs = delayInNanos / MSTONANOS ;
				} else {
					// Something wrong, we are not considering this
					delayInNanos = 9999;
					delayInMs = 9999;
				}
			} else if (tx_pktno == 0 || tx_pktno < rx_pktno) {
				printf("Tx GPIO interrupt is not received \n");
				if (tx_pktno < rx_pktno) {
					tx_pktno = rx_pktno;
				}
			}

#ifdef DEBUG
			// Calculate wait time <-- can be used to calculate linux stack delay
			if (end_time.tv_nsec >= start_time.tv_nsec
					&& end_time.tv_sec >= start_time.tv_sec) {
				diffInSec = (end_time.tv_sec - start_time.tv_sec);
				diffInNanos = (end_time.tv_nsec - start_time.tv_nsec);

			} else if (start_time.tv_nsec > end_time.tv_nsec
					&& end_time.tv_sec >= start_time.tv_sec) {
				diffInSec = (end_time.tv_sec - start_time.tv_sec);
				diffInNanos =
						((BILLION - start_time.tv_nsec) + end_time.tv_nsec);

			} else {
				// 1 sec ... something wrong
				diffInSec = 9999;
				diffInNanos = 9999;
			}

			// Times
			if(tx_pktno == rx_pktno) {
				printf("Got a packet [%d] at %ld.%09ld sec"
						"(waiting %ld.%09ld sec) "
						"tx->rx : %ld.%09ld sec\n",
						rx_pktno, end_time.tv_sec, end_time.tv_nsec,
						diffInSec, diffInNanos, delayInSec, delayInNanos);
			} else {
				printf("Got a packet [%d] at %ld.%09ld sec"
						"(waiting %ld.%09ld sec)\n",
						rx_pktno, end_time.tv_sec, end_time.tv_nsec,
						diffInSec, diffInNanos);
			}

			// Dump the packet
			pktdump(packet, pktlength);
#else
			// Times
			if(tx_pktno == rx_pktno) {
				printf("[%d] @ %ld.%09ld "
					//": %ld \n", rx_pktno, end_time.tv_sec, end_time.tv_nsec, delayInNanos);
					": %lf \n", rx_pktno, end_time.tv_sec, end_time.tv_nsec, delayInMs);
			} else {
				printf("[%d] @ %ld.%09ld : Error\n",
						rx_pktno, end_time.tv_sec, end_time.tv_nsec);
			}
#endif

			// Check for max number of pkts
			if (packno >= max_packno || tx_pktno >= max_packno || rx_pktno >= max_packno) {
				running = -1;
			}
		}
	}

	printf("\n Let finish ....\n");

	// make sure gpio is low
	ret = mraa_gpio_write(gpio, 0);
	if (ret != MRAA_SUCCESS) {
		mraa_result_print(ret);
	}

	// Stop the current interrupt watcher
    ret = mraa_gpio_isr_exit(timePin);
	if (ret != MRAA_SUCCESS) {
		mraa_result_print(ret);
	}

	// close gpio
	ret = mraa_gpio_close(gpio);
	if (ret != MRAA_SUCCESS) {
		mraa_result_print(ret);
	}

	// close pcap
	pcap_close(handle);

	return ret;
}

#ifdef DEBUG
// packet dump
void pktdump(const u_char * pu8, int nLength) {
	char sz[256], szBuf[512], szChar[17], *buf;
	//char fFirst = 1;
	unsigned char baaLast[2][16];
	unsigned int n, nPos = 0, nStart = 0, nLine = 0;
	//unsigned int nSameCount = 0;

	buf = szBuf;
	szChar[0] = '\0';

	for (n = 0; n < nLength; n++) {
		baaLast[(nLine & 1) ^ 1][n & 0xf] = pu8[n];
		if ((pu8[n] < 32) || (pu8[n] >= 0x7f))
			szChar[n & 0xf] = '.';
		else
			szChar[n & 0xf] = pu8[n];
		szChar[(n & 0xf) + 1] = '\0';
		nPos += sprintf(&sz[nPos], "%02X ", baaLast[(nLine & 1) ^ 1][n & 0xf]);
		if ((n & 15) != 15)
			continue;
		/*
		        if ((memcmp(baaLast[0], baaLast[1], 16) == 0) && (!fFirst)) {
		                nSameCount++;
		        } else {
		                if (nSameCount)
		                        buf += sprintf(buf, "(repeated %d times)\n",
		                                nSameCount);
		*/
						buf += sprintf(buf, "%04x: %s %s\n", nStart, sz, szChar);
						//nSameCount = 0;
						printf("%s", szBuf);
						buf = szBuf;
		//        }
		nPos = 0;
		nStart = n + 1;
		nLine++;
		//fFirst = 0;
		sz[0] = '\0';
		szChar[0] = '\0';
	}
	/*
	if (nSameCount)
	        buf += sprintf(buf, "(repeated %d times)\n", nSameCount);
	*/
	buf += sprintf(buf, "%04x: %s", nStart, sz);
	if (n & 0xf) {
		*buf++ = ' ';
		while (n & 0xf) {
			buf += sprintf(buf, "   ");
			n++;
		}
	}
	buf += sprintf(buf, "%s\n", szChar);
	printf("%s", szBuf);
}
#endif
