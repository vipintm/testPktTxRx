/*
 * testPktTxRx general config
 */

#ifndef SRC_CONFIG_H_
#define SRC_CONFIG_H_


// Config
//#define DEBUG 1
//#define STRIG_DATA 1
//#define SYSFSGPIO 1
//#define TX99 1
//#define CREATECSV 1
//#define READENV 1
#define TESTON 1
//
#define WLANDEV "mon0"
//
#define MAGIC_ID 0xf6f7 // TODO use this for filtering instead of MAC??
#define nDelay  100000 // 1000000 <- this is too much
#define IOPIN 8 // using gpio pin 40 (IO08)
#define TRGPIN 9 // using gpio pin ?? (IO09)
#define DATA_SZ 32 // (old : 200) first test data
#define DATA_STEP 32 // data size to increse
#define DATA_MAX 512 // Maximum size of data
#define TEST_PER 10 // No of test to run on same data size
#define WAIT_DELAY 1 // seconds
#define THR_WAIT_TIME 10 // 5 * WAIT_DELAY
//
#define SRC_IP "192.168.1.1"
#define DST_IP "255.255.255.255"
#define SRC_PORT 50505
#define DST_PORT 50505

// TX99
#define TX99_POWER 20

#endif /* SRC_CONFIG_H_ */
