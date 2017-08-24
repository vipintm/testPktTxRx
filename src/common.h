/*
 * Some common code
 */

#ifndef SRC_COMMON_H_
#define SRC_COMMON_H_

// Constants
#define BILLION  1000000000L // <- nano
#define MSTONANOS 1000000L
#define SECTOMS	1000L
#define IN  0
#define OUT 1
#define LOW  0
#define HIGH 1
#define START 1
#define STOP 0


// GPIO functions
#ifdef SYSFSGPIO
static int GPIOExport(int pin);
static int GPIOUnexport(int pin);
static int GPIODirection(int pin, int dir);
static int GPIORead(int pin);
static int GPIOWrite(int pin, int value);
#endif

// TX99 functions
#ifdef TX99
int TX99setpower(int power);
int TX99status(void);
int TX99set(int value);
#endif

#endif /* SRC_COMMON_H_ */
