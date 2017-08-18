/*
 * testPktTxRx general config
 */

#ifndef SRC_CONFIG_H_
#define SRC_CONFIG_H_


// Config
//#define DEBUG 1
//#define STRIG_DATA 1
//
#define WLANDEV "mon0"
//
#define nDelay  1000000 // 1000000 <- this is too much
#define IOPIN 8 // using gpio pin 40 (IO08)
#define TRGPIN 9 // using gpio pin ?? (IO09)
#define DATA_SZ 32 // (old : 200) first test data
#define DATA_STEP 32 // data size to increse
#define DATA_MAX 512 // Maximum size of data
#define TEST_PER 10 // No of test to run on same data size
//
#define SRC_IP "192.168.1.1"
#define DST_IP "255.255.255.255"
#define SRC_PORT 50505
#define DST_PORT 50505

#endif /* SRC_CONFIG_H_ */
