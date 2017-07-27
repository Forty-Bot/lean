#include "lean.h"

#include <endian.h>
#include <errno.h>
#include <error.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#include <uuid/uuid.h>

int write_at_sector_mmap(int fd, uint64_t sec, const void *buf, size_t n)
{
	static int mmap_fd = -1;
	static void *mmap_addr;
	off_t length;

	if (fd != mmap_fd) {
		length = lseek(fd, 0L, SEEK_END);
		if (length < 0)
			return -1;

		mmap_addr = mmap(NULL, length, PROT_WRITE, MAP_SHARED, fd, 0);
		if (mmap_addr == MAP_FAILED)
			return -1;

		mmap_fd = fd;
	}

	memcpy(mmap_addr + sec * LEAN_SEC, buf, n);
	return 0;
}

/*
 * Writes n bytes of data stored in buf to a sector on fd
 * Returns 0 on success, -1 on system failure, and -2 on write failure
 * errno may contain the error on failure
 */
int write_at_sector_seek(int fd, uint64_t sec, const void *buf, size_t n)
{
	int ret = 0; /* Our return value */
	int err_save = 0; /* A saved value of errno */
	ssize_t wr; /* Return value of write() */

	if (lseek(fd, sec * LEAN_SEC, SEEK_SET) < 0) {
		err_save = errno;
		ret = -1;
		goto end;
	}
	while (n > 0) {
		wr = write(fd, buf, n);
		if (wr < 0) {
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
	if (fsync(fd)) {
		/* Don't save the errno if we already errored */
		if (err_save == 0)
			err_save = errno;
		ret = -1;
	}
	errno = err_save;
	return ret;
}

#define write_at_sector write_at_sector_mmap

/*
 * Set the first n bits of a bitmap to 1
 */
void fill_bitmap(uint8_t *bm, uint64_t n)
{
	uint64_t i; /* Iterator */

	for (i = 0; n > 8; i++) {
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
uint64_t generate_bm(int fd, struct lean_sb_info *sb)
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
	bands = 1 + (sb->sectors_total - 1)/band_sec;

	bm_size = band_sec / 8;
	bm = malloc(bm_size);
	if (!bm)
		error(-1, errno, "Could not allocate memory for bitmap");
	memset(bm, 0, bm_size);

	/* Write the band 0 bitmap */
	sb->bitmap_start = sb->super_primary + 1;
	sb->root = sb->bitmap_start + band_bm_sec;
	/* We should subtract 1 here. but it's added back in because
	 * block numbers start at 0
	 */
	zero_sec = sb->root + sb->prealloc;
	fill_bitmap(bm, zero_sec);
	/* [initial sectors (including band 0's bitmap)] + [superblock backup],
	 * [each band's bitmap - band 0's bitmap] */
	sb->sectors_free = sb->sectors_total -
			   (zero_sec + 1 + (bands - 1) * band_bm_sec);
	sb->super_backup = ((sb->sectors_total < band_sec) ?
			     sb->sectors_total : band_sec) - 1;
	set_sec(bm, sb->super_backup);
	if (write_at_sector(fd, sb->bitmap_start, bm, bm_size))
		error(-1, errno, "Unable to write band zero bitmap");

	/* Because all band bitmaps (except band 0's) are identical,
	 * we can create one bitmap and write it to bands 1 to bands
	 */
	memset(bm, 0, bm_size);
	fill_bitmap(bm, band_bm_sec);

	for (i = 1; i < bands; i++) {
		if (write_at_sector(fd, i * band_sec, bm, bm_size)) {
			error(-1, errno,
			      "Unable to write band %"PRIu64" bitmap", i);
		}
	}
	return 0;
}

/*
 * Generate a new filesystem on device fd
 * returns 0 on success
 */
int generate_fs(int fd, uint8_t sb_offset, uint8_t prealloc,
	uint8_t log2_band_sec, const uuid_t uuid,
	const uint8_t *volume_label, uint64_t sec)
{
	size_t data_size; /* Root directory data size */
	struct lean_dir_entry *data; /* Root directory data */
	struct lean_ino_info *root; /* The root directory */
	struct lean_inode *root_ino;
	struct lean_superblock *sb; /* The superblock */
	struct lean_sb_info *sbi;
	struct timespec ts; /* Timespec returned by clock_gettime */
	int64_t time; /* Current time in microseconds */

	sbi = malloc(sizeof(*sbi));
	sb = malloc(sizeof(*sb));
	if (!sbi || !sb)
		error(-1, errno, "Could not allocate memory for superblock");
	memset(sbi, 0, sizeof(*sbi));

	sbi->prealloc = prealloc;
	sbi->log2_band_sectors = log2_band_sec;
	sbi->state = LEAN_STATE_CLEAN;
	memcpy(sbi->uuid, uuid, 16);
	strncpy(sbi->volume_label, volume_label, 63);
	sbi->volume_label[63] = '\0';
	sbi->sectors_total = sec;
	sbi->super_primary = sb_offset;
	if (generate_bm(fd, sbi))
		error(-1, 0, "Could not write bitmap to disk");

	data_size = 2 * sizeof(*data);
	root = malloc(sizeof(*root));
	root_ino = malloc(sizeof(*root_ino) + data_size);
	if (!root || !root_ino)
		error(-1, errno, "Could not allocate memory for root inode");
	data = (struct lean_dir_entry *) (&root_ino[1]);
	memset(root_ino, 0, sizeof(*root_ino) + data_size);

	root->extent_count = 1;
	root->link_count = 2;
	root->uid = getuid();
	root->gid = getgid();
	root->attr = LIA_RUSR | LIA_WUSR | LIA_XUSR |
		     LIA_PREALLOC | LIA_FMT_DIR;
	root->size = data_size;
	root->sector_count = prealloc;
	clock_gettime(CLOCK_REALTIME, &ts);
	time = lean_time(ts);
	root->time_access = time;
	root->time_status = time;
	root->time_modify = time;
	root->time_create = time;
	root->extent_starts[0] = sbi->root;
	root->extent_sizes[0] = prealloc;

	data[0].inode = htole64(sbi->root);
	data[0].type = LFT_DIR;
	data[0].entry_length = 1;
	data[0].name_length = htole16(1);
	data[0].name[0] = '.';
	data[1].inode = htole64(sbi->root);
	data[1].type = LFT_DIR;
	data[1].entry_length = 1;
	data[1].name_length = htole16(2);
	data[1].name[0] = '.';
	data[1].name[1] = '.';

	lean_info_to_inode(root, root_ino);
	write_at_sector(fd, sbi->root, root_ino, sizeof(*root_ino) + data_size);

	lean_info_to_superblock(sbi, sb);
	write_at_sector(fd, sbi->super_primary, sb, sizeof(*sb));
	write_at_sector(fd, sbi->super_backup, sb, sizeof(*sb));

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
int parse_long(const char *str, long *n)
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
			error(0, 0, "Error parsing \"%s\" at character %td",
			      str, endp - str);
			ret = -1;
		}
	} else {
		ret = -1;
	}
	return ret;
}

const char help_msg[] =
"Usage: mkfs.lean [OPTION]... DEVICE\n"
"Format a disk as a LEAN filesystem\n"
"OPTIONS:\n"
"\t-b sectors-per-band\n"
"\t-f superblock-offset\n"
"\t-n volume-label\n"
"\t-p preallocated-sectors\n"
"\t-U UUID\n"
"\t-h\n";

int main(int argc, char **argv)
{
	bool band_sec_set = false; /* Set if -b is passed */
	char *device; /* The name of the target device */
	char volume_name[64] = ""; /* The volume name */
	char uuid_string[37]; /* The string representation of the UUID */
	int c; /* The option returned by UUID */
	int fd; /* The file descriptor of the device */
	long log2_band_sec = 0; /* log2(Sectors in a band) */
	long bands;
	long band_sec; /* Sectors in a band */
	long new_band_sec; /* Possible new value of sectors in a band */
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
			if (band_sec < 4096 ||
				(band_sec & (band_sec - 1))) {
				error(-1, 0,
				      "Sectors per band must be greater than or equal to 4096 and a power of 2");
			}
			break;
		case 'f':
			if (parse_long(optarg, &sb_offset))
				return -1;
			if (sb_offset < 1 || sb_offset > 32) {
				error(-1, 0,
				      "The superblock offset must be between 1 and 32 (inclusive)");
			}
			break;
		case 'h':
			printf(help_msg);
			return 0;
		case 'n':
			strncpy(volume_name, optarg, 63);
			volume_name[63] = '\0';
			break;
		case 'p':
			if (parse_long(optarg, &prealloc))
				return -1;
			if (prealloc < 1 || prealloc > 256) {
				error(-1, 0,
				      "Between 1 and 256 sectors must be preallocated");
			}
			break;
		case 'U':
			if (uuid_parse(optarg, uuid)) {
				error(0, 0,
				      "Unable to parse UUID \"%s\"; generating one automatically",
				      optarg);
			}
			break;
		case '?':
			return -1;
		default:
			error(-1, 0, "Invalid option -%c\n%s", c, help_msg);
		}
	}

	/* Don't use error() here for output consistency */
	if (optind >= argc || !argv[optind]) {
		fprintf(stderr, help_msg);
		return -1;
	}

	device = argv[optind];
	fd = open(device, O_EXCL | O_RDWR);
	if (fd < 0)
		error(-1, errno, "Error opening %s", device);

	size = lseek(fd, 0L, SEEK_END);
	/* We need at least 4k to fit everything in */
	if (!(size >> 12))
		error(-1, 0, "%s is too small! (only %lu bytes)", device, size);

	/* Round size to the nearest multiple of 512 */
	sectors = size >> 9;
	size = sectors << 9;

	/* Try to keep bands below 256 while the band size is not greater than
	 * 64 sectors
	 */
#define MiB ((1024 * 1024) / 512)
#define GiB ((1024 * 1024 * 1024) / 512)
	if (!band_sec_set) {
		if (sectors <= 512 * MiB)
			band_sec = 1 << 12;
		else if (sectors <= 4 * GiB)
			band_sec = 1 << 15;
		else
			band_sec = 1 << 18;
	}
#undef MiB
#undef GiB

	/* Reduce band_sec if a smaller size would only use one band */
	new_band_sec = upper_power_of_two(sectors);
	if (new_band_sec > band_sec)
		new_band_sec = band_sec;
	if (new_band_sec < 4096)
		new_band_sec = 4096;
	if (new_band_sec != band_sec) {
		printf("Using %lu sectors per band instead of %lu because only one band is needed\n",
		       new_band_sec, band_sec);
		band_sec = new_band_sec;
	}
	bands = 1 + (sectors - 1)/band_sec;

	if (uuid_is_null(uuid))
		uuid_generate(uuid);
	uuid_unparse(uuid, uuid_string);

	printf("Formatting %s with the following options:\n"
	       "Size:             %lu\n"
	       "Sectors:          %lu\n"
	       "Bands :           %lu\n"
	       "Sectors per band: %lu\n"
	       "UUID:             %s\n"
	       "Volume label:     %s\n",
	       device, size, sectors, bands, band_sec, uuid_string,
	       volume_name);

	/* Compute log2(band_sec) */
	while (band_sec >>= 1)
		log2_band_sec++;

	return generate_fs(fd, sb_offset, prealloc, log2_band_sec, uuid,
			   volume_name, sectors);
}
