#ifndef DRIVER_H
#define DRIVER_H

#include "lean.h"

#include <linux/fs.h>

/*
 * Convert lean_inode_attribute mask to a umode_t
 */
static inline umode_t LEAN_M(uint32_t attr)
{
	umode_t mode;
	mode = attr & LIA_POSIX_MASK;
	mode |= -((attr & LIA_FMT_REG) == LIA_FMT_REG) & S_IFREG;
	mode |= -((attr & LIA_FMT_DIR) == LIA_FMT_DIR) & S_IFDIR;
	mode |= -((attr & LIA_FMT_SYM) == LIA_FMT_SYM) & S_IFLNK;
	pr_err("Converted attr %x to mode %x\n", attr, mode);
	return mode;
}

/* super.c */
struct inode *lean_inode_alloc(struct super_block *s);

/* inode.c */
struct inode *lean_iget(struct super_block *s, uint64_t ino);

#endif /* DRIVER_H */
