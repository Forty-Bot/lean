#include "lean.h"

#include <errno.h>
#include <error.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#include <uuid/uuid.h>

/*
 * Writes n bytes of data stored in buf to a sector on fd
 * Returns 0 on success, -1 on system failure, and -2 on write failure
 * errno may contain the error on failure
 */
int write_at_sector(int fd, uint64_t sec, const void *buf, size_t n)
{
	int ret = 0; /* Our return value */
	int err_save = 0; /* A saved value of errno */
	ssize_t wr; /* Return value of write() */
	if(lseek(fd, sec * 512, SEEK_SET) < 0) {
		err_save = errno;
		ret = -1;
		goto end;
	}
	while((wr = write(fd, buf, n))) {
		if(wr < 0) {
			err_save = errno;
			ret = -1;
			goto end;
		} else if (wr == 0) {
			ret = -2;
			goto end;
		}
		n -= wr;
		buf += wr;
	}
end:
	if(fsync(fd)) {
		/* Don't save the errno if we already errored */
		if(err_save == 0)
			err_save = errno;
		ret = -1;
	}
	errno = err_save;
	return ret;
}

/*
 * Set the first n bits of a bitmap to 1
 */
void fill_bitmap(uint8_t *bm, uint64_t n)
{
	uint64_t i; /* Iterator */
	for(i = 0; n > 8; i++) {
		bm[i] = 0xFF;
		n -= 8;
	}
	bm[i] = (1 << n) - 1;
}

/*
 * Set a sector as in use
 */
void set_sec(uint8_t *bm, uint64_t sec)
{
	bm[sec >> 3] ^= 1 << (sec & 7);
}

/*
 * Generate a bitmap for a new filesystem and write it to disk
 * Fills in the sectors_free, super_backup, bitmap_start, and root fields of sb 
 * returns 0 on success
 */
uint64_t generate_bm(int fd, struct lean_superblock *sb)
{
	size_t bm_size; /* Size of the band bitmap size */
	uint8_t *bm; /* Bitmap of bands 1 to bands */
	uint64_t i; /* Iterator */
	uint64_t bands; /* Total number of bands */
	uint64_t band_sec; /* Number of sectors in a band */
	uint64_t band_bm_sec; /* Number of sectors to hold a band's bitmap */
	uint64_t zero_sec; /* Number of used sectors in band zero */
	
	band_sec = 1 << sb->log2_band_sectors;
	band_bm_sec = band_sec >> 12;
	bands = 1 + (sb->sectors_total - 1) / band_sec;
	
	bm_size = band_sec / 8;
	bm = malloc(bm_size);
	if(!bm)
		error(-1, errno, "Could not allocate memory for bitmap");
	memset(bm, 0, bm_size);

	/* Write the band 0 bitmap */
	sb->bitmap_start = sb->root + 1;
	sb->root = sb->bitmap_start + band_bm_sec;
	/* We should subtract 1 here. but it's added back in because
	 * block numbers start at 0 */
	zero_sec = sb->root + sb->prealloc;
	fill_bitmap(bm, zero_sec);
	sb->sectors_free = zero_sec + (bands - 1) * band_bm_sec;
	sb->super_backup = ((sb->sectors_total < band_sec) ? \
		sb->sectors_total : band_sec) - 1;
	set_sec(bm, sb->super_backup);
	if(write_at_sector(fd, sb->bitmap_start, bm, bm_size))
		error(-1, errno, "Unable to write band zero bitmap");

	/* Because all band bitmaps (except band 0's) are identical,
	 * we can create one bitmap and write it to bands 1 to bands */
	memset(bm, 0, bm_size);
	fill_bitmap(bm, band_bm_sec);

	for(i = 1; i < bands; i++) {
		if(write_at_sector(fd, i * band_sec, bm, bm_size))
			error(-1, errno, "Unable to write band %ld bitmap", i);
	}
	return 0;
}

/*
 * Generate a new filesystem on device fd
 * returns 0 on success
 */
int generate_fs(int fd, uint8_t sb_offset, uint8_t prealloc, \
	uint8_t log2_band_sec, const uuid_t uuid, \
	const uint8_t *volume_label, uint64_t sec)
{
	size_t data_size; /* Root directory data size */
	struct lean_dir_entry *data; /* Root directory data */
	struct lean_inode *root; /* The root directory */
	struct lean_superblock *sb; /* The superblock */
	struct timespec ts; /* Timespec returned by clock_gettime */
	int64_t time; /* Current time in microseconds */
	
	sb = malloc(sizeof(*sb));
	if(!sb)
		error(-1, errno, "Could not allocate memory for superblock");
	memset(sb, 0, sizeof(*sb));

	memcpy(sb->magic, &LEAN_MAGIC_SUPERBLOCK, sizeof(LEAN_MAGIC_SUPERBLOCK));
	memcpy(sb->fs_version, &LEAN_VERSION, sizeof(LEAN_VERSION));
	sb->prealloc = prealloc - 1;
	sb->log2_band_sectors = log2_band_sec;
	memcpy(sb->uuid, uuid, 16);
	strncpy(sb->volume_label, volume_label, 63);
	sb->volume_label[63] = '\0';
	sb->sectors_total = sec;
	sb->super_primary = sb_offset;
	if(generate_bm(fd, sb))
		error(-1, 0, "Could not write bitmap to disk");
	sb->checksum = lean_checksum(sb, sizeof(*sb));
	
	data_size = 2 * sizeof(*data);
	root = malloc(sizeof(*root) + data_size);
	if(!root)
		error(-1, errno, "Could not allocate memory for root inode");
	data = (struct lean_dir_entry *) (&root[1]);
	memset(root, 0, sizeof(*root) + data_size);

	memcpy(root->magic, &LEAN_MAGIC_INODE, sizeof(LEAN_MAGIC_INODE));
	root->extent_count = 1;
	root->link_count = 1;
	root->uid = getuid();
	root->gid = getgid();
	root->attr = LIA_RUSR | LIA_WUSR | LIA_XUSR | LIA_PREALLOC | LIA_FMT_DIR;
	root->size = data_size;
	root->sector_count = prealloc;
	clock_gettime(CLOCK_REALTIME, &ts);
	time = (ts.tv_sec * 1000000L) + (ts.tv_nsec / 1000);
	root->time_access = time;
	root->time_status = time;
	root->time_modify = time;
	root->time_create = time;
	root->extent_starts[0] = sb->root;
	root->extent_sizes[0] = prealloc;
	root->checksum = lean_checksum(root, sizeof(*root));

	data[0].inode = sb->root;
	data[0].type = LFT_DIR;
	data[0].entry_length = 1;
	data[0].name_length = 1;
	data[0].name[0] = '.';
	data[1].inode = sb->root;
	data[1].type = LFT_DIR;
	data[1].entry_length = 1;
	data[1].name_length = 2;
	data[1].name[0] = '.';
	data[1].name[1] = '.';

	write_at_sector(fd, sb->root, root, sizeof(*root) + data_size);
	write_at_sector(fd, sb->super_primary, sb, sizeof(*sb));
	write_at_sector(fd, sb->super_backup, sb, sizeof(*sb));

	return 0;
}

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
int parse_long(const char* str, long* n)
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
			error(0, 0, "Error parsing \"%s\" at character %ld", \
				str, endp - str);
			ret = -1;
		}
	} else {
		ret = -1;
	}
	return ret;
}

const char help_msg[] = 
"Usage: mkfs.lean [ -b sectors-per-band | -f superblock-offset | -n volume-label | -p preallocated-sectors | -U UUID | -h ] device\n";

int main(int argc, char **argv)
{
	char *device; /* The name of the target device */
	char volume_name[64] = ""; /* The volume name */
	char uuid_string[37]; /* The string representation of the UUID */
	int c; /* The option returned by UUID */
	int fd; /* The file descriptor of the device */
	long log2_band_sec = 0; /* log2(Sectors in a band) */
	long band_sec = 1 << 18; /* Sectors in a band */
	long new_band_sec = 0; /* Possible new value of sectors in a band */
	long prealloc = 8; /* Sectors to preallocate */
	long sb_offset = 1; /* Sector the suberblock resides in */
	long sectors; /* Total sectors on the device */
	off_t size; /* Size of the device in bytes */
	uuid_t uuid; /* UUID to use */
	
	uuid_clear(uuid);

	while ((c = getopt(argc, argv, "b:f:hn:p:U:")) != -1) {
		switch (c) {
		case 'b':
			if (parse_long(optarg, &band_sec))
				return -1;
			if (band_sec < 4096 || \
				(band_sec & (band_sec - 1)))
				error(-1, 0, "Sectors per band must be a greater than 4096 and a power of 2");
			break;
		case 'f':
			if (parse_long(optarg, &sb_offset))
				return -1;
			if (sb_offset < 1 || sb_offset > 32)
				error(-1, 0, "The superblock offset must be between 1 and 32 (inclusive)");
			break;
		case 'h':
			printf(help_msg);
			return 0;
		case 'n':
			strncpy(volume_name, optarg, 63);
			volume_name[63] = '\0';
			break;
		case 'p':
			if(parse_long(optarg, &prealloc)) 
				return -1;
			if(prealloc < 1 || prealloc > 256)
				error(-1, 0, "Between 1 and 256 sectors must be preallocated");
			break;
		case 'U':
			if(uuid_parse(optarg, uuid))
				error(0, 0, "Unable to parse UUID \"%s\"; generating one automatically", \
					optarg);
			break;
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
	sectors = size >> 9;
	size = sectors << 9;
	
	/* Reduce band_sec if a smaller size would only use one band */
	new_band_sec = upper_power_of_two(sectors);
	if(new_band_sec > band_sec)
		new_band_sec = band_sec;
	if(new_band_sec < 4096)
		new_band_sec = 4096;
	if(new_band_sec != band_sec) {
		printf("Using %ld sectors per band instead of %ld because only one band is needed\n", \
			new_band_sec, band_sec);
		band_sec = new_band_sec;
	}

	if(uuid_is_null(uuid))
		uuid_generate(uuid);
	uuid_unparse(uuid, uuid_string);
	
	printf("Formatting %s with the following options:\n"
		"Size:                 %ld\n"
		"Sectors:              %ld\n"
		"Superblock offset:    %ld\n"
		"Sectors per band:     %ld\n"
		"Preallocated sectors: %ld\n"
		"UUID:                 %s\n"
		"Volume label:         %s\n", \
		device, size, sectors, sb_offset, band_sec, \
		prealloc, uuid_string, volume_name);

	/* Compute log2(band_sec) */
	while(band_sec >>= 1) {
		log2_band_sec++;
	}

	return generate_fs(fd, sb_offset, prealloc, log2_band_sec, uuid, \
		volume_name, sectors);
}
