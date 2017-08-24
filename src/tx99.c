/*
 * Support func for tx99 tests
 */

//
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
//
#include "config.h"
#include "common.h"

#define BUFFER_MAX 3
#define DIRECTION_MAX 35
#define VALUE_MAX 30

int TX99setpower(int power) {

	char buffer[BUFFER_MAX];
	ssize_t bytes_written;
	int fd;

	fd = open("/sys/kernel/debug/ieee80211/phy0/ath9k/tx99_power", O_WRONLY);
	if (-1 == fd) {
		fprintf(stderr, "Failed to open TX99 power sys fs for writing!\n");
		return(-1);
	}

	bytes_written = snprintf(buffer, BUFFER_MAX, "%d", power);
	write(fd, buffer, bytes_written);
	close(fd);
	return(0);
}

int TX99status(void) {

	char path[VALUE_MAX];
	char value_str[3];
	int fd;

	snprintf(path, VALUE_MAX, " /sys/kernel/debug/ieee80211/phy0/ath9k/tx99");
	fd = open(path, O_RDONLY);
	if (-1 == fd) {
		fprintf(stderr, "Failed to open TX99 sys fs for reading!\n");
		return(-1);
	}

	if (-1 == read(fd, value_str, 3)) {
		fprintf(stderr, "Failed to read value!\n");
		return(-1);
	}

	close(fd);

	return(atoi(value_str));
}

int TX99set(int value) {

	static const char s_values_str[] = "01";

	char path[VALUE_MAX];
	int fd;

	snprintf(path, VALUE_MAX, "/sys/kernel/debug/ieee80211/phy0/ath9k/tx99");
	fd = open(path, O_WRONLY);
	if (-1 == fd) {
		fprintf(stderr, "Failed to open TX99 sys fs for writing!\n");
		return(-1);
	}

	if (1 != write(fd, &s_values_str[LOW == value ? 0 : 1], 1)) {
		fprintf(stderr, "Failed to write value!\n");
		return(-1);
	}

	close(fd);
	return(0);
}
