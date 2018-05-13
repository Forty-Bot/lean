#include "user.h"
#include "lean.h"
#include "find.h"

#include <assert.h>
#include <bsd/stdlib.h>
#include <error.h>
#include <fcntl.h>
#include <fts.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

/*
 * This function returns the sector which is immediately after the end
 * of the last extent in an inode
 */
static uint64_t find_next_sector(struct lean_ino_info *li)
{
	return li->extent_starts[li->extent_count - 1]
		+ li->extent_sizes[li->extent_count - 1];
}

uint64_t extend_inode(struct lean_sb_info *sbi, struct lean_ino_info *li,
		      uint32_t *count)
{
	uint64_t sector;

	assert(*count <= (uint32_t)1 << 31);

	sector = find_next_sector(li);
	sector = alloc_sectors(sbi, sector, count);
	if (errno)
		return 0;

	if (sector == li->extent_starts[li->extent_count - 1]
			+ li->extent_sizes[li->extent_count - 1]) {
		li->extent_sizes[li->extent_count - 1] += *count;
	} else {
		/* We need to add another extent */
		if (li->extent_count >= 6) {
			fprintf(stderr, "Cannot create more than 6 extents");
			errno = ERANGE;
			return 0;
		}
		li->extent_starts[li->extent_count] = sector;
		li->extent_sizes[li->extent_count] = *count;
		li->extent_count++;
	}

	return sector;
}

/* XXX Must only be called on freshly-created directories! */
void create_dotfiles(struct lean_sb_info *sbi, struct lean_ino_info *parent,
		     struct lean_ino_info *dir)
{
	if (add_link(sbi, dir, dir, ".", 1)
	    || add_link(sbi, dir, parent, "..", 2))
	    error(0, errno, "Could not create dot directories(!)");
}

/*
 * Create a file from an FTSENT. Acts as a wrapper around create_inode_stat.
 * After calling this you must
 *	1. Initialize any filetype-specific data
 *	2. Call write_inode (or put_inode)
 */
struct lean_ino_info *create_inode_ftsent(struct lean_sb_info *sbi, FTSENT *f)
{
	struct lean_ino_info *dir =
		(struct lean_ino_info *)f->fts_parent->fts_pointer;
	struct lean_ino_info *li;
	struct statx stat;

	if (statx(AT_FDCWD, f->fts_accpath, 0, STATX_ALL, &stat)) {
		int errsv = errno;

		error(0, errno, "Error stat-ing file \"%s\"",
		      f->fts_path);
		errno = errsv;
		return NULL;
	}

	li = create_inode_stat(sbi, dir, &stat);
	if (!li)
		return NULL;
	if (add_link(sbi, dir, li, f->fts_name, f->fts_namelen))
		return NULL;

	return li;
}

/*
 * Creates a regular file
 */
struct lean_ino_info *create_file(struct lean_sb_info *sbi, FTSENT *f)
{
	bool first = true;
	int fd;
	loff_t off = 0;
	struct lean_ino_info *li;
	uint64_t size;

	li = create_inode_ftsent(sbi, f);
	if (!li)
		return li;
	size = li->size;

	fd = open(f->fts_accpath, O_RDONLY);
	if (fd == -1) {
		error(0, errno, "Could not open \"%s\" for reading",
		      f->fts_path);
		goto err;
	}

	/* The outer loop allocates sectors which the inner loop copies data
	 * into
	 */
	while (size > 0) {
		loff_t doff;
		uint64_t sector;
		uint64_t copy_size;

		if (!first) {
			uint32_t count =
				(size + LEAN_SEC_MASK) >> LEAN_SEC_SHIFT;

			sector = extend_inode(sbi, li, &count);
			if (!sector) {
				error(0, errno,
				      "Could not extend inode of \"%s\"",
				      f->fts_path);
				goto err;
			}
			copy_size = min(count << LEAN_SEC_SHIFT, size);
			doff = sector * LEAN_SEC;
		} else {
			first = false;
			sector = li->extent_starts[0];
			copy_size = min(LEAN_SEC - sizeof(struct lean_inode),
					size);
			doff = sector * LEAN_SEC + sizeof(struct lean_inode);
		}

		while (copy_size > 0) {
			ssize_t n = copy_file_range(fd, &off, sbi->fd, &doff,
					    copy_size, 0);

			if (n == -1) {
				error(0, errno,
				      "Error copying data from file \"%s\"",
				      f->fts_path);
				goto err;
			}

			size -= n;
			copy_size -= n;
		}
	}

	return li;

err:
	free(li);
	return NULL;
}

/*
 * Initializes a new directory
 */
struct lean_ino_info *create_dir(struct lean_sb_info *sbi, FTS *fts, FTSENT *f)
{
	FTSENT *child = fts_children(fts, FTS_NAMEONLY);
	struct lean_ino_info *li;
	int64_t size = 0;

	li = create_inode_ftsent(sbi, f);
	if (!li)
		return li;

	/* Original directory size is nonsense */
	li->size = 0;
	create_dotfiles(sbi, (struct lean_ino_info *)f->fts_parent->fts_pointer,
			li);

	/* Try to allocate all the space for direntries up front */
	for (; child; child = child->fts_link)
		size += LEAN_DIR_ENTRY_LEN(child->fts_namelen);
	while (size > 0) {
		uint32_t count = (size + LEAN_SEC_MASK) >> LEAN_SEC_SHIFT;
		uint64_t res;

		errno = 0;
		res = extend_inode(sbi, li, &count);
		if (res == 0) {
			free(li);
			return NULL;
		}

		size -= count * LEAN_SEC;
	}

	return li;
}

int write_inode(struct lean_sb_info *sbi, struct lean_ino_info *li)
{
	struct lean_inode *inode = LEAN_I(sbi, li);

	memcpy(inode, li, sizeof(*inode));
	return 0;
}

/* TODO: Search for empty dentries instead of just appending */
int add_link(struct lean_sb_info *sbi, struct lean_ino_info *dir,
	     struct lean_ino_info *inode, uint8_t *name, uint8_t name_length)
{
	struct lean_dir_entry *de;
	uint8_t entry_length = LEAN_DIR_ENTRY_LEN(name_length);
	uint64_t sector = dir->extent_starts[dir->extent_count - 1]
			  + dir->extent_sizes[dir->extent_count - 1] - 1;
	unsigned int off = (sector == dir->extent_starts[0])
			   ? sizeof(struct lean_inode) + dir->size
			   : dir->size & LEAN_SEC_MASK;

	if (entry_length > LEAN_SEC - off) {
		uint32_t count = 0;

		sector = extend_inode(sbi, dir, &count);
		if (sector == 0)
			return -1;
		off = 0;
	}

	de = (struct lean_dir_entry *)&sbi->disk[sector * LEAN_SEC + off];
	de->inode = htole64(inode->extent_starts[0]);
	de->type = (inode->attr & LIA_FMT_MASK) >> LIA_FMT_SHIFT;
	de->entry_length = entry_length;
	de->name_length = htole16(name_length);
	memcpy(de->name, name, name_length);

	dir->size += entry_length;
	inode->link_count++;

	return 0;
}

/*
 * Try to spread top-level directories, but keep subdirectories together for
 * locality. For more information, see src/inode.c
 */
static uint64_t find_goal_dir(struct lean_sb_info *sbi,
			      struct lean_ino_info *parent)
{
	if (parent->extent_starts[0] == sbi->root)
		return arc4random_uniform(sbi->band_count) * sbi->band_sectors;
	else
		return parent->extent_starts[0];
}

/* This isn't ideal (we want to spread files around the disk, and this will
 * bunch them up in a linear fasion), but it's ok at creation.
 */
static uint64_t find_goal_other(struct lean_sb_info *sbi,
				struct lean_ino_info *parent)
{
	return parent->extent_starts[0];
}

struct lean_ino_info *create_inode_stat(struct lean_sb_info *sbi,
					struct lean_ino_info *dir,
					struct statx *stat)
{
	struct lean_ino_info *inode;
	uint32_t count = sbi->prealloc;
	uint64_t sec;

	inode = malloc(sizeof(struct lean_ino_info));
	if (!inode)
		return NULL;

	sec = S_ISDIR(stat->stx_mode) ? find_goal_dir(sbi, dir)
				      : find_goal_other(sbi, dir);

	sec = alloc_sectors(sbi, sec, &count);
	if (errno)
		goto err;

	inode->indirect_count = 0;
	inode->indirect_first = 0;
	inode->indirect_last = 0;
	inode->fork = 0;
	inode->link_count = 0;
	inode->uid = stat->stx_uid;
	inode->gid = stat->stx_gid;

	/* TODO: use an ioctl like in lsattr */
	inode->attr = stat->stx_mode & LIA_POSIX_MASK;
	if (S_ISREG(stat->stx_mode))
		inode->attr |= LIA_FMT_REG;
	if (S_ISDIR(stat->stx_mode))
		inode->attr |= LIA_FMT_DIR;
	if (S_ISLNK(stat->stx_mode))
		inode->attr |= LIA_FMT_SYM;

	inode->size = stat->stx_size;
	inode->sector_count = count;

	inode->time_access = lean_timex(stat->stx_atime);
	inode->time_status = lean_timex(stat->stx_ctime);
	inode->time_modify = lean_timex(stat->stx_mtime);
	inode->time_create = lean_timex(stat->stx_btime);

	inode->extent_count = 1;
	inode->extent_starts[0] = sec;
	inode->extent_sizes[0] = count;

	return inode;

err:
	free(inode);
	return NULL;
}

/* This is similar to lean_try_alloc_iter, except we don't need to worry about
 * concurrency */
static uint32_t try_alloc(uint8_t *bitmap, uint32_t size,
			  uint32_t goal, uint32_t *count)
{
	bool greedy = false;
	uint32_t sector; /* Local sector */
	uint32_t bitsize = size * 8;
	uint8_t *tmp;
	unsigned i;

	if (goal) {
		greedy = true;
		goto bitwise;
	}

bytewise:
	tmp = memchr(bitmap, 0, size);
	if (tmp) {
		sector = (tmp - bitmap) * 8;
		goto found;
	}

bitwise:
	sector = find_next_zero_bit((size_t *)bitmap, bitsize, goal);
	if (sector < bitsize)
		goto found;
	if (greedy) {
		greedy = false;
		goto bytewise;
	}

	*count = 0;
	return 0;

found:
	for (i = 0; i < *count; i++)
		if (test_and_set_bit(sector + i, (size_t *)bitmap))
			break;

	*count = i;
	return sector;
}

uint64_t alloc_sectors(struct lean_sb_info *sbi, uint64_t goal,
		       uint32_t *count)
{
	unsigned i;
	uint8_t *bitmap;
	uint32_t band_tgt;
	uint32_t size;
	uint64_t alloc;
	uint64_t band;
	uint64_t ret;


	if (goal <= sbi->root || goal > sbi->sectors_total)
		goal = sbi->root;
	band = goal >> sbi->log2_band_sectors;
	band_tgt = goal & (sbi->band_sectors - 1);

	for (i = 0; i < sbi->band_count; i++, band++) {
		if (band >= sbi->band_count)
			band = 0;

		bitmap = LEAN_BITMAP(sbi, band);
		size = LEAN_BITMAP_SIZE(sbi, band);
		alloc = try_alloc(bitmap, size, band_tgt, count);
		if (alloc)
			break;

		band_tgt = 0;
	}

	if (!alloc) {
		errno = ENOSPC;
		*count = 0;
		return 0;
	}

	ret = alloc + band * sbi->band_sectors;

	/* If we get one of these errors, something has gone horribly wrong;
	 * just crash with an error.
	 */
	if (alloc < sbi->bitmap_size) {
		error(-1, 0,
		      "allocated %"PRIu32" blocks at sector %"PRIu64
		      ", part of band %"PRIu64"'s bitmap",
		      *count, ret, band);
	}
	if (ret + *count > sbi->sectors_total || ret <= sbi->root) {
		error(-1, 0,
		      "allocated %"PRIu32" blocks at sector %"PRIu64
		      ", outside the data zone",
		      *count, ret);
	}

	sbi->sectors_free -= *count;
	return ret;
}
