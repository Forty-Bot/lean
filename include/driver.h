#ifndef DRIVER_H
#define DRIVER_H

#include "lean.h"

#include <linux/fs.h>

/*
 * Extract a struct lean_ino_info from a struct inode
 */
static inline struct lean_ino_info *LEAN_I(struct inode *inode)
{
	return (struct lean_ino_info *) inode;
}

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
	return mode;
}

static inline unsigned LEAN_DT(enum lean_file_type type) {
	switch(type) {
	case LFT_REG:
		return DT_REG;
	case LFT_DIR:
		return DT_DIR;
	case LFT_SYM:
		return DT_LNK;
	case LFT_NONE:
	default:
		return DT_UNKNOWN;
	}
}

/* super.c */
struct inode *lean_inode_alloc(struct super_block *s);

/* inode.c */
struct inode *lean_iget(struct super_block *s, uint64_t ino);

/* file.c */
extern const struct file_operations lean_file_ops;

/* dir.c */
extern const struct file_operations lean_dir_ops;
extern const struct inode_operations lean_dir_inode_ops;

#endif /* DRIVER_H */
