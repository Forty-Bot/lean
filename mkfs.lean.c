#include "leanfs.h"

#include <errno.h>
#include <error.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

/*
 * Rounds to the next highest power of 2
 */
uint64_t upper_power_of_two(uint64_t v)
{
	v--;
	v |= v >> 1;
	v |= v >> 2;
	v |= v >> 4;
	v |= v >> 8;
	v |= v >> 16;
	v |= v >> 32;
	v++;
	return v;
}

/*
 * Parses a long from a string
 */
int parse_long(char* str, long* n)
{
	int ret = 0;
	char *endp;
	if (str && n) {
		errno = 0;
		*n = strtol(str, &endp, 10);
		if (errno) {
			error(0, errno, "Error parsing \"%s\"", str);
			ret = -1;
		}
		if (endp[0] != '\0' || str[0] == '\0') {
			error(0, 0, "Error parsing \"%s\" at %ld", \
				str, endp - str);
			ret = -1;
		}
	} else {
		ret = -1;
	}
	return ret;
}

const char help_msg[] = 
"Usage: mkfs.lean [ -b sectors-per-band | -f superblock-offset | -h ] device\n";

int main(int argc, char **argv)
{
	char *device;
	int c;
	int fd;
	long band_sectors = 1 << 18;
	long new_band_sectors = 0;
	long sb_offset = 1;
	off_t size;
	while ((c = getopt(argc, argv, "b:f:h")) != -1) {
		switch (c) {
		case 'b':
			if (optarg) {
				if (parse_long(optarg, &band_sectors))
					return -1;
				if (band_sectors < 4096 || \
					(band_sectors & (band_sectors - 1)))
					error(-1, 0, "Sectors per band must be a greater than 4096 and a power of 2");
			} else {
				error(-1, 0, "Error parsing -b");
			}
			break;
		case 'f':
			if (optarg) {
				if (parse_long(optarg, &sb_offset))
					return -1;
				if (sb_offset < 1 || sb_offset > 32)
					error(-1, 0, "The superblock offset must be between 1 and 32 (inclusive)");
			} else {
				error(-1, 0, "Error parsing -f");
			}
			break;
		case 'h':
			printf(help_msg);
			return 0;
		case '?':
			return -1;
		default:
			error(-1, 0, "Invalid option -%c\n%s", c, help_msg);
		}
	}
	
	device = argv[optind];
	/* Don't use error() here for output consistency */
	if (!device) {
		fprintf(stderr, help_msg);
		return -1;
	}

	fd = open(device, O_EXCL | O_RDWR);
	if (fd < 0)
		error(-1, errno, "Error opening %s", device);
	
	size = lseek(fd, 0L, SEEK_END);
	/* We need at least 4k to fit everything in */
	if(!(size >> 12))
		error(-1, 0, "%s is too small! (only %ld bytes)", device, size);
	
	/* Round size to the nearest multiple of 512 */
	size = (size >> 9) << 9;
	/* Reduce band_sectors if a smaller size would only use one band */
	new_band_sectors = upper_power_of_two(size);
	if(new_band_sectors < band_sectors) {
		printf("Using %ld sectors per band instead of %ld because only one band is needed\n", \
			new_band_sectors, band_sectors);
		band_sectors = new_band_sectors;
	}
	
	printf("Formatting %s with the following options:\n"
		"Size:              %ld\n"
		"Superblock Offset: %ld\n"
		"Sectors per band:  %ld\n", \
		device, size, sb_offset, band_sectors);

	return 0;
}
