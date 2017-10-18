#include "user.h"
#include "lean.h"

#include <assert.h>
#include <endian.h>
#include <errno.h>
#include <error.h>
#include <fcntl.h>
#include <fts.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>
#include <uuid/uuid.h>

/*
 * Error policy:
 * Everything which happens before we have a complete working filesystem on disk
 * can just exit with an error code and let the OS do the cleanup. After
 * generate_fs finishes, try to recover/retry if possible, but always leave a
 * consistent disk state.
 */

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
void toggle_sec(uint8_t *bm, uint64_t sec)
{
	bm[sec >> 3] ^= 1 << (sec & 7);
}

/*
 * Generate a bitmap for a new filesystem and write it to disk
 * Fills in the sectors_free, super_backup, bitmap_start, and root fields of sb
 * returns 0 on success
 */
uint64_t generate_bm(struct lean_sb_info *sbi)
{
	size_t bm_size; /* Size of the band bitmap size */
	uint8_t *bm; /* Bitmap of bands 1 to bands */
	uint64_t i; /* Iterator */
	uint64_t bands; /* Total number of bands */
	uint64_t band_sec; /* Number of sectors in a band */
	uint64_t band_bm_sec; /* Number of sectors to hold a band's bitmap */
	uint64_t zero_sec; /* Number of used sectors in band zero */

	band_sec = 1 << sbi->log2_band_sectors;
	band_bm_sec = band_sec >> 12;
	bands = 1 + (sbi->sectors_total - 1)/band_sec;

	bm_size = band_sec / 8;
	bm = malloc(bm_size);
	if (!bm)
		error(-1, errno, "Could not allocate memory for bitmap");
	memset(bm, 0, bm_size);

	/* Write the band 0 bitmap */
	sbi->bitmap_start = sbi->super_primary + 1;
	sbi->root = sbi->bitmap_start + band_bm_sec;
	/* We should subtract 1 here. but it's added back in because
	 * block numbers start at 0
	 */
	zero_sec = sbi->root + sbi->prealloc;
	fill_bitmap(bm, zero_sec);
	/* [initial sectors (including band 0's bitmap)] + [superblock backup],
	 * [each band's bitmap - band 0's bitmap] */
	sbi->sectors_free = sbi->sectors_total -
			   (zero_sec + 1 + (bands - 1) * band_bm_sec);
	sbi->super_backup = ((sbi->sectors_total < band_sec) ?
			     sbi->sectors_total : band_sec) - 1;
	toggle_sec(bm, sbi->super_backup);
	memcpy(&sbi->disk[sbi->bitmap_start * LEAN_SEC], bm, bm_size);

	/* Because all band bitmaps (except band 0's) are identical,
	 * we can create one bitmap and write it to bands 1 to bands
	 */
	memset(bm, 0, bm_size);
	fill_bitmap(bm, band_bm_sec);

	for (i = 1; i < bands; i++)
		memcpy(&sbi->disk[i * band_sec * LEAN_SEC], bm, bm_size);

	free(bm);
	return 0;
}

/*
 * Generate a new filesystem
 * returns 0 on success
 */
int generate_fs(struct lean_sb_info *sbi,
		struct lean_ino_info **rootp)
{
	size_t data_size; /* Root directory data size */
	struct lean_dir_entry *data; /* Root directory data */
	struct lean_ino_info *root; /* The root directory */
	struct lean_inode *root_ino;
	struct lean_superblock *sb =
		(struct lean_superblock *)
		&sbi->disk[sbi->super_primary * LEAN_SEC];
	struct timespec ts; /* Timespec returned by clock_gettime */
	int64_t time; /* Current time in microseconds */

	sbi->state = LEAN_STATE_CLEAN;
	if (generate_bm(sbi))
		error(-1, 0, "Could not write bitmap to disk");

	data_size = 2 * sizeof(*data);
	root_ino = (struct lean_inode *) &sbi->disk[sbi->root * LEAN_SEC];
	root = malloc(sizeof(*root));
	if (!root)
		error(-1, errno, "Could not allocate memory for root inode");
	*rootp = root;
	data = (struct lean_dir_entry *) (&root_ino[1]);
	memset(root_ino, 0, sizeof(*root_ino) + data_size);

	root->extent_count = 1;
	root->link_count = 2;
	root->uid = getuid();
	root->gid = getgid();
	root->attr = LIA_RUSR | LIA_WUSR | LIA_XUSR |
		     LIA_PREALLOC | LIA_FMT_DIR;
	root->size = 0;
	root->sector_count = sbi->prealloc;
	clock_gettime(CLOCK_REALTIME, &ts);
	time = lean_time(ts);
	root->time_access = time;
	root->time_status = time;
	root->time_modify = time;
	root->time_create = time;
	root->extent_starts[0] = sbi->root;
	root->extent_sizes[0] = sbi->prealloc;

	create_dotfiles(sbi, root, root);

	lean_info_to_inode(root, root_ino);

	lean_info_to_superblock(sbi, sb);
	memcpy(&sbi->disk[sbi->super_backup * LEAN_SEC], sb, sizeof(*sb));

	return 0;
}

int populate_fs(struct lean_sb_info *sbi,
		struct lean_ino_info *root, FTS *fts)
{
	FTSENT *f;
	int attempts = 0;

	/* XXX: fts_read sets errno whenever it returns NULL, unlike readdir! */
	while ((f = fts_read(fts))) {
		if (f->fts_level <= 0) {
			f->fts_pointer = root;
			continue;
		}
	
retry:
		switch (f->fts_info) {
		case FTS_NS:
			/* what? */
		case FTS_DNR:
		case FTS_ERR: {
			/* If we have an individual file error, retry a few
			 * times then give up and skip it */
			int errsv = errno;
			error(0, errno,
			      "Error while populating disk at \"%s\" (attempt %d)",
			      f->fts_path, ++attempts);
			if (errsv == EAGAIN && attempts <= 4) {
				fts_set(fts, f, FTS_AGAIN);
				f = fts_read(fts);
				if (!f)
					goto out;
				goto retry;
			} else {
				attempts = 0;
				fts_set(fts, f, FTS_SKIP);
			}
		}
		case FTS_D:
			f->fts_pointer = create_dir(sbi, fts, f);
			if (!f->fts_pointer)
				goto out;
			break;
		case FTS_DC:
			add_link(sbi, (struct lean_ino_info *)f->fts_pointer,
				 (struct lean_ino_info *)f->fts_cycle->fts_link);
			break;
		case FTS_DP:
			put_inode(sbi, (struct lean_ino_info *)f->fts_pointer);
			break;
		case FTS_F:
		case FTS_NSOK: {
			struct lean_ino_info *li = create_file(sbi, f);
			if (!li)
				goto out;
			put_inode(sbi, li);
			break;
		}
		case FTS_SL:
		case FTS_SLNONE:
			/* TODO: Implement symbolic links */
		case FTS_DOT:
			/* what? */
		case FTS_DEFAULT:
		default:
			fprintf(stderr,
				"Unsupported file type for file \"%s\"", 
			        f->fts_path);
		}
		attempts = 0;
	}

out:
	if (errno)
		error(-1, errno,
		      "Error populating disk. Filesystem state undefined");

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

#define HELP_MSG "Usage: %s [OPTION]... DEVICE\n" \
"Format a disk as a LEAN filesystem\n" \
"OPTIONS:\n" \
"\t-b sectors-per-band\n" \
"\t-d base-directory\n" \
"\t-f superblock-offset\n" \
"\t-n volume-label\n" \
"\t-p default-allocated-sectors\n" \
"\t-U UUID\n" \
"\t-h print this help message\n"

int main(int argc, char **argv)
{
	bool band_sec_set = false; /* Set if -b is passed */
	char *device; /* The name of the target device */
	char uuid_string[37]; /* The string representation of the UUID */
	FTS *fts = NULL;
	int c; /* The option returned by UUID */
	int ret;
	long bands;
	long band_sec; /* Sectors in a band */
	long new_band_sec; /* Possible new value of sectors in a band */
	long prealloc;
	off_t size; /* Size of the device in bytes */
	struct lean_sb_info *sbi;
	struct lean_ino_info *root;
	uuid_t uuid; /* UUID to use */

	sbi = malloc(sizeof(*sbi));
	if (!sbi)
		error(-1, errno, "Could not allocate memory for superblock");
	memset(sbi, 0, sizeof(*sbi));
	sbi->super_primary = 1;
	sbi->prealloc = 8; /* Sectors to preallocate */

	uuid_clear(uuid);

	while ((c = getopt(argc, argv, "b:d:f:hn:p:U:")) != -1) {
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
		case 'd':
			{
				char *paths[] = {optarg, NULL};

				fts = fts_open(paths, FTS_COMFOLLOW
						      | FTS_PHYSICAL
						      | FTS_NOSTAT, NULL);
				if (!fts)
					error(-1, errno,
					      "Could not open \"%s\" for traversal",
					      optarg);
			}
			break;
		case 'f':
			if (parse_long(optarg, &sbi->super_primary))
				return -1;
			if (sbi->super_primary < 1 || sbi->super_primary > 32) {
				error(-1, 0,
				      "The superblock offset must be between 1 and 32 (inclusive)");
			}
			break;
		case 'h':
			printf(HELP_MSG, argv[0]);
			return 0;
		case 'n':
			strncpy(sbi->volume_label, optarg, 63);
			sbi->volume_label[63] = '\0';
			break;
		case 'p':
			if (parse_long(optarg, &prealloc))
				return -1;
			if (sbi->prealloc < 1 || sbi->prealloc > 256) {
				error(-1, 0,
				      "Between 1 and 256 sectors must be preallocated");
			}
			sbi->prealloc = prealloc;
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
			error(-1, 0, "Invalid option -%c\n" HELP_MSG,
			      c, argv[0]);
		}
	}

	/* Don't use error() here for output consistency */
	if (optind >= argc || !argv[optind]) {
		fprintf(stderr, HELP_MSG, argv[0]);
		return -1;
	}

	device = argv[optind];
	sbi->fd = open(device, O_EXCL | O_RDWR);
	if (sbi->fd < 0)
		error(-1, errno, "Error opening %s", device);

	size = lseek(sbi->fd, 0L, SEEK_END);
	/* We need at least 4k to fit everything in */
	if (!(size >> 12))
		error(-1, 0, "%s is too small! (only %lu bytes)", device, size);

	/* Round size to the nearest multiple of 512 */
	sbi->sectors_total = size >> 9;
	size = sbi->sectors_total << 9;

	/* Try to keep bands below 256 while the band size is not greater than
	 * 64 sectors
	 */
#define MiB ((1024 * 1024) / 512)
#define GiB ((1024 * 1024 * 1024) / 512)
	if (!band_sec_set) {
		if (sbi->sectors_total <= 512 * MiB)
			band_sec = 1 << 12;
		else if (sbi->sectors_total <= 4 * GiB)
			band_sec = 1 << 15;
		else
			band_sec = 1 << 18;
	}
#undef MiB
#undef GiB

	/* Reduce band_sec if a smaller size would only use one band */
	new_band_sec = upper_power_of_two(sbi->sectors_total);
	if (new_band_sec > band_sec)
		new_band_sec = band_sec;
	if (new_band_sec < 4096)
		new_band_sec = 4096;
	if (new_band_sec != band_sec) {
		printf("Using %lu sectors per band instead of %lu because only one band is needed\n",
		       new_band_sec, band_sec);
		band_sec = new_band_sec;
	}
	bands = 1 + (sbi->sectors_total - 1)/band_sec;

	if (uuid_is_null(uuid))
		uuid_generate(uuid);
	uuid_unparse(uuid, uuid_string);
	memcpy(sbi->uuid, uuid, sizeof(sbi->uuid));

	printf("Formatting %s with the following options:\n"
	       "Size:             %lu\n"
	       "Sectors:          %lu\n"
	       "Bands :           %lu\n"
	       "Sectors per band: %lu\n"
	       "UUID:             %s\n"
	       "Volume label:     %s\n",
	       device, size, sbi->sectors_total, bands, band_sec, uuid_string,
	       sbi->volume_label);

	/* Compute log2(band_sec) */
	while (band_sec >>= 1)
		sbi->log2_band_sectors++;
	sbi->band_sectors = band_sec;
	sbi->band_count = bands;

	sbi->disk = mmap(NULL, size, PROT_WRITE, MAP_SHARED, sbi->fd, 0);
	if (sbi->disk == MAP_FAILED)
		error(-1, errno, "Failed to mmap file");

	ret = generate_fs(sbi, &root);
	if (ret)
		return ret;

	if (fts) {
		printf("Writing initial data to disk\n");
		ret = populate_fs(sbi, root, fts);
	}
	return ret;
}
