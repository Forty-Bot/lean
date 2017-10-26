#include "user.h"
#include "lean.h"

#include <assert.h>
#include <error.h>
#include <fcntl.h>
#include <fts.h>
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

	assert(*count <= 1 << 31);

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
	struct lean_dir_entry *data = (struct lean_dir_entry *) (&inode[1]);
	
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
 *	2. Call write_inode
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
	add_link(sbi, (struct lean_ino_info *)f->fts_pointer, li,
		 f->fts_name, f->fts_namelen);

	return li;
}

/*
 * Creates a regular file
 */
struct lean_ino_info *create_file(struct lean_sb_info *sbi, FTSENT *f)
{
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

	while (size > 0) {
		ssize_t n = size;
		loff_t doff;
		uint32_t count = (n + LEAN_SEC_MASK) >> LEAN_SEC_SHIFT;
		uint64_t sector = extend_inode(sbi, li, &count);

		if (!sector) {
			error(-1, errno, "Could not extend inode of \"%s\"",
			      f->fts_path);
			goto err;
		}

		doff = sector * LEAN_SEC;
		n = copy_file_range(fd, &off, sbi->fd, &doff,
				    n < count ? n : count, 0);
		if (n == -1) {
			error(-1, errno, "Error copying data from file \"%s\"",
				f->fts_path);
			goto err;
		}

		size -= n;
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
	for(; child; child = child->fts_link)
		size += LEAN_DIR_ENTRY_LEN(child->fts_namelen);
	while (size > 0) {
		uint32_t count = (size + LEAN_SEC_MASK) >> LEAN_SEC_SHIFT;
		uint64_t res;
		
		errno = 0;
		res = extend_inode(sbi, li, &count);
		if (res == 0 && errno != 0) {
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
