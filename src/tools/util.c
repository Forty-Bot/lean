#include "user.h"
#include "lean.h"

#include <assert.h>
#include <error.h>
#include <fcntl.h>
#include <fts.h>
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

/* XXX:Must only be called on freshly-created directories! */
void create_dotfiles(struct lean_sb_info *sbi, struct lean_ino_info *parent,
		     struct lean_ino_info *dir)
{
	struct lean_inode *inode = LEAN_I(sbi, dir);
	struct lean_dir_entry *data = (struct lean_dir_entry *)(&inode[1]);

	dir->size += LEAN_DOTFILES_SIZE;
	memset(data, 0, LEAN_DOTFILES_SIZE);

	data[0].inode = htole64(dir->extent_starts[0]);
	data[0].type = LFT_DIR;
	data[0].entry_length = 1;
	data[0].name_length = htole16(1);
	data[0].name[0] = '.';
	data[1].inode = htole64(parent->extent_starts[0]);
	data[1].type = LFT_DIR;
	data[1].entry_length = 1;
	data[1].name_length = htole16(2);
	data[1].name[0] = '.';
	data[1].name[1] = '.';
}

/*
 * Create a file from an FTSENT. Acts as a wrapper around create_inode_stat.
 * After calling this you must
 *	1. Initialize any filetype-specific data
 *	2. Call write_inode (or put_inode)
 */
struct lean_ino_info *create_inode_ftsent(struct lean_sb_info *sbi, FTSENT *f)
{
	struct lean_ino_info *li;
	struct statx stat;

	if (!statx(AT_FDCWD, f->fts_accpath, 0,
		   STATX_ALL, &stat)) {
		int errsv = errno;

		error(0, errno, "Error stat-ing file \"%s\"",
		      f->fts_path);
		errno = errsv;
		return NULL;
	}

	li = create_inode_stat(sbi, &stat);
	if (add_link(sbi, (struct lean_ino_info *)f->fts_pointer, li,
		     f->fts_name, f->fts_namelen))
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
	create_dotfiles(sbi, (struct lean_ino_info *)f->fts_pointer, li);

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

	return 0;
}