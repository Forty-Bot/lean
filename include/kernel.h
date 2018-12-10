#ifndef KERNEL_H
#define KERNEL_H

#include "lean.h"

#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/version.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 13, 0)
#define lean_write_page(page, sync) write_one_page(page, sync)
#else
#define lean_write_page(page, sync) write_one_page(page)
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 18, 0)
#define timespec timespec64
#define lean_time lean_time64
#define lean_timespec lean_timespec64
#endif

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

static inline enum lean_file_type LEAN_FT(umode_t mode)
{
	mode &= S_IFMT;
	switch (mode) {
	case S_IFREG:
		return LFT_REG;
	case S_IFDIR:
		return LFT_DIR;
	case S_IFLNK:
		return LFT_SYM;
	default:
		return LFT_NONE;
	}
}

static inline uint8_t LEAN_DT(enum lean_file_type type)
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

/*
 * Keeps track of a band-sized chunk of pages backed by the sector bitmap
 * off is only non-zero if len is less than PAGE_SIZE. This is because multiple
 * bands worth of bitmap may be located within one page
 */
struct lean_bitmap {
	/* protects writes (but not reads) to both ->free and ->pages */
	spinlock_t lock;
	uint32_t off;
	uint32_t free;
	uint32_t len;
	struct page *pages[];
};

#define lean_set_bit_atomic ext2_set_bit_atomic
#define lean_clear_bit_atomic ext2_clear_bit_atomic

#define LEAN_BITMAP_PAGES(sbi) (((sbi)->bitmap_size * LEAN_SEC + ~PAGE_MASK) \
	>> PAGE_SHIFT)
#define LEAN_BITMAP_SIZE(sbi) (sizeof(struct lean_bitmap) \
	+ LEAN_BITMAP_PAGES(sbi) * sizeof(struct page *))
static inline struct lean_bitmap *LEAN_BITMAP(struct lean_sb_info *sbi,
					      uint64_t band)
{
	return ((void *)sbi->bitmap_cache) + band * LEAN_BITMAP_SIZE(sbi);
}

#define LEAN_ROUND_PAGE(s) (((s) + ~PAGE_MASK) & PAGE_MASK)

extern struct kmem_cache *lean_extra_cache;

static inline struct lean_extra_info *lean_extra_get(void)
{
	return kmem_cache_alloc(lean_extra_cache, GFP_KERNEL);
}

static inline void lean_extra_put(struct lean_extra_info *ex)
{
	kmem_cache_free(lean_extra_cache, ex);
}

/* super.c */
struct inode *lean_inode_alloc(struct super_block *s);
extern __printf(3, 4)
void lean_msg(struct super_block *s, const char *prefix, const char *fmt, ...);

/* inode.c */
struct inode *lean_iget(struct super_block *s, uint64_t ino);
int lean_write_inode(struct inode *inode, struct writeback_control *wbc);
int lean_setattr(struct dentry *de, struct iattr *attr);
int lean_extend_inode(struct inode *inode, uint64_t *sector, uint32_t *count);
struct inode *lean_new_inode(struct inode *dir, umode_t mode);
int lean_set_page_dirty(struct page *page);

/* file.c */
extern const struct file_operations lean_file_ops;
extern const struct inode_operations lean_file_inode_ops;

/* dir.c */
extern const struct file_operations lean_dir_ops;
extern const struct inode_operations lean_dir_inode_ops;

/* alloc.c */
void __lean_bitmap_put(struct lean_bitmap *bitmap, int count);
static inline void lean_bitmap_put(struct lean_bitmap *bitmap)
{
	__lean_bitmap_put(bitmap, LEAN_ROUND_PAGE(bitmap->len) >> PAGE_SHIFT);
}

struct lean_bitmap *lean_bitmap_get(struct super_block *s, uint64_t band);
uint32_t lean_bitmap_getfree(struct lean_bitmap *bitmap);
int lean_bitmap_cache_init(struct super_block *s);
void lean_bitmap_cache_destroy(struct super_block *s);
uint64_t lean_count_free_sectors(struct super_block *s);
uint64_t lean_new_sectors(struct super_block *s, uint64_t goal, uint32_t *count,
			  int *errp);
void lean_free_sectors(struct super_block *s, uint64_t start, uint32_t count);
uint64_t lean_new_zeroed_sectors(struct super_block *s, uint64_t goal,
				 uint32_t *count, int *errp);

#endif /* KERNEL_H */
