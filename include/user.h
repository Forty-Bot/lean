#ifndef USER_H
#define USER_H

#include "lean.h"

#include <errno.h>
#include <features.h>
#include <fts.h>
#include <limits.h>
#include <linux/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
/* The copy_file_range() system call first appeared in Linux 4.5, but glibc 2.27
 * provides a user-space emulation when it is not available.
 */
#if __GLIBC__ && __GLIBC_PREREQ(2,27)
#define _GNU_SOURCE
#define WANT_COPY_FILE_RANGE
#endif
#include <unistd.h>

/* Function wrappers for syscalls not yet in glibc */
static inline int statx(int dirfd, const char *pathname, int flags,
			unsigned int mask, struct statx *statxbuf)
{
	return syscall(SYS_statx, dirfd, pathname, flags, mask, statxbuf);
}

#ifdef WANT_COPY_FILE_RANGE
static inline loff_t copy_file_range(int fd_in, loff_t *off_in, int fd_out,
				     loff_t *off_out, size_t len,
				     unsigned int flags)
{
	return syscall(SYS_copy_file_range, fd_in, off_in, fd_out, off_out,
		       len, flags);
}
#endif

#define max(a, b) \
__extension__ ({ \
	 __typeof__(a) _a = (a); \
	 __typeof__(b) _b = (b); \
	 _a > _b ? _a : _b; \
})

#define min(a, b) \
__extension__ ({ \
	 __typeof__(a) _a = (a); \
	 __typeof__(b) _b = (b); \
	 _a < _b ? _a : _b; \
})

#define BITS_PER_SIZE_T (sizeof(size_t) * CHAR_BIT)
#define BITMAP_FIRST_WORD_MASK(start) (~((size_t)0) \
				       << ((start) & (BITS_PER_SIZE_T - 1)))
#define BIT_MASK(nr) (((size_t)1) << ((nr) % BITS_PER_SIZE_T))
#define BIT_WORD(nr) ((nr) / BITS_PER_SIZE_T)

/**
 * test_and_set_bit - Set a bit and return its old value
 * @nr: Bit to set
 * @addr: Address to count from
 */
static inline int test_and_set_bit(int nr, size_t *addr)
{
	size_t mask = BIT_MASK(nr);
	size_t *p = addr + BIT_WORD(nr);
	size_t old;

	old = *p;
	*p = old | mask;

	return (old & mask) != 0;
}

/* XXX: LEAN_I and LEAN_BITMAP have different (but similar) meaning than in
 * kernel.h */
#define LEAN_I(sbi, inode) ((struct lean_inode *) \
			    &sbi->disk[inode->extent_starts[0] * LEAN_SEC])

static inline uint8_t *LEAN_BITMAP(struct lean_sb_info *sbi, uint64_t band)
{
	uint64_t sector;

	if (band != 0)
		sector = sbi->bitmap_start;
	else
		sector = band * sbi->band_sectors;
	return &sbi->disk[sector * LEAN_SEC];
}

/* Size of the bitmap in bytes */
static inline uint32_t LEAN_BITMAP_SIZE(struct lean_sb_info *sbi, uint64_t band)
{
	if (band + 1 < sbi->band_count)
		return sbi->band_sectors >> 3;
	else
		/* The last bitmap may be cut short */
		return (sbi->sectors_total - band * sbi->band_sectors) >> 3;
}

/* Note to implementers: use errno to return errors */
uint64_t alloc_sectors(struct lean_sb_info *sbi, uint64_t goal,
		       uint32_t *count);
struct lean_ino_info *create_inode_stat(struct lean_sb_info *sbi,
					struct lean_ino_info *dir,
					struct statx *stat);
int add_link(struct lean_sb_info *sbi, struct lean_ino_info *dir,
	     struct lean_ino_info *inode, uint8_t *name, uint8_t namelen);

uint64_t extend_inode(struct lean_sb_info *sbi, struct lean_ino_info *li,
		      uint32_t *count);
void create_dotfiles(struct lean_sb_info *sbi, struct lean_ino_info *parent,
		     struct lean_ino_info *dir);
int write_inode(struct lean_sb_info *sbi, struct lean_ino_info *li);
struct lean_ino_info *create_inode_ftsent(struct lean_sb_info *sbi, FTSENT *f);
struct lean_ino_info *create_file(struct lean_sb_info *sbi, FTSENT *f);
struct lean_ino_info *create_dir(struct lean_sb_info *sbi, FTS *fts, FTSENT *f);

static inline int put_inode(struct lean_sb_info *sbi, struct lean_ino_info *li)
{
	int ret = write_inode(sbi, li);

	free(li);
	return ret;
}

#endif /* USER_H */
