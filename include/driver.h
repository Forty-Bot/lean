#ifndef DRIVER_H
#define DRIVER_H

#include "lean.h"

#include <linux/fs.h>

/*
 * Extract a struct lean_ino_info from a struct inode
 */
static inline struct lean_ino_info *LEAN_I(struct inode *inode)
{
	return list_entry(inode, struct lean_ino_info, vfs_inode);
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

struct lean_bitmap {
	uint32_t free;
	void *start;
	struct page *first;
};

/* super.c */
struct inode *lean_inode_alloc(struct super_block *s);
extern __printf(3, 4)
void lean_msg(struct super_block *, const char *, const char *, ...);

/* inode.c */
struct inode *lean_iget(struct super_block *s, uint64_t ino);
int lean_write_inode(struct inode *inode, struct writeback_control *wbc);
int lean_setattr(struct dentry *de, struct iattr *attr);

/* file.c */
extern const struct file_operations lean_file_ops;
extern const struct inode_operations lean_file_inode_ops;

/* dir.c */
extern const struct file_operations lean_dir_ops;
extern const struct inode_operations lean_dir_inode_ops;

/* balloc.c */
extern const struct address_space_operations lean_bitmap_aops;
void lean_put_bitmap(struct lean_bitmap *bitmap);
struct lean_bitmap *lean_get_bitmap(struct super_block *s, uint64_t band);

#endif /* DRIVER_H */
