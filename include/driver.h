#ifndef DRIVER_H
#define DRIVER_H

#include "lean.h"

#include <linux/fs.h>

/* 
 * Locks *must* be taken in the following order:
 * sbi->lock
 * bitmap->lock
 */

/*
 * Extract a struct lean_ino_info from a struct inode
 */
static inline struct lean_ino_info *LEAN_I(struct inode *inode)
{
	return list_entry(inode, struct lean_ino_info, vfs_inode);
}

static inline unsigned int LEAN_DT(enum lean_file_type type)
{
	switch (type) {
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

#define LEAN_BITMAP_PAGES(sbi) (((sbi)->bitmap_size * LEAN_SEC + ~PAGE_MASK) \
	>> PAGE_SHIFT)
#define LEAN_BITMAP_SIZE(sbi) (sizeof(struct lean_bitmap) \
	+ LEAN_BITMAP_PAGES(sbi) * sizeof(struct page *))
#define LEAN_BITMAP(sbi, band) (((void *) sbi->bitmap_cache) \
	+ band * LEAN_BITMAP_SIZE(sbi))
#define LEAN_ROUND_PAGE(s) ((s + ~PAGE_MASK) & PAGE_MASK)

/*
 * ->lock protects writes (but not reads) to both ->free and ->pages
 */
struct lean_bitmap {
	spinlock_t lock;
	uint32_t off;
	uint32_t free;
	uint32_t len;
	struct page *pages[];
};

/* super.c */
struct inode *lean_inode_alloc(struct super_block *s);
extern __printf(3, 4)
void lean_msg(struct super_block *s, const char *prefix, const char *fmt, ...);

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
void __lean_bitmap_put(struct lean_bitmap *bitmap, int count);
#define lean_bitmap_put(bitmap) \
	__lean_bitmap_put((bitmap), LEAN_ROUND_PAGE((bitmap)->len) >> PAGE_SHIFT)
struct lean_bitmap *lean_bitmap_get(struct super_block *s, uint64_t band);
uint32_t lean_bitmap_getfree(struct super_block *s, struct lean_bitmap *bitmap);
int lean_bitmap_cache_init(struct super_block *s);
void lean_bitmap_cache_destroy(struct super_block *s);
uint64_t lean_count_free_sectors(struct super_block *s);

#endif /* DRIVER_H */
