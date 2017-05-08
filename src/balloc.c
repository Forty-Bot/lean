#include "driver.h"
#include "lean.h"

#include <linux/buffer_head.h>
#include <linux/mpage.h>
#include <linux/mutex.h>
#include <linux/pagemap.h>
#include <linux/slab.h>

/* We map the entire bitmap to a contiguous address_space
 * This avoid dealing with bios or buffer_heads ourselves
 */
static int lean_get_bitmap_block(struct inode *inode, sector_t sec,
	struct buffer_head *bh_result, int create)
{
	struct super_block *s = inode->i_sb;
	struct lean_sb_info *sbi = s->s_fs_info;
	uint64_t band = sec / sbi->bitmap_size;
	uint64_t band_sec = band * sbi->band_sectors
		+ sec
		- (band * sbi->bitmap_size);

	if (band >= sbi->band_count || band_sec >= sbi->sectors_total ||
		sec >= sbi->band_count * sbi->band_sectors)
		return -ENXIO;

	if (band == 0)
		band_sec += sbi->bitmap_start;

	map_bh(bh_result, s, band_sec);
	return 0;
}

static int lean_write_bitmap_page(struct page *page,
	struct writeback_control *wbc)
{
	return mpage_writepage(page, lean_get_bitmap_block, wbc);
}

static int lean_read_bitmap_page(struct file *file, struct page *page)
{
	return mpage_readpage(page, lean_get_bitmap_block);
}

static int lean_write_bitmap_pages(struct address_space *mapping,
	struct writeback_control *wbc)
{
	return mpage_writepages(mapping, wbc, lean_get_bitmap_block);
}

static int lean_read_bitmap_pages(struct file *file,
	struct address_space *mapping, struct list_head *pages,
	unsigned int nr_pages)
{
	return mpage_readpages(mapping, pages, nr_pages, lean_get_bitmap_block);
}

const struct address_space_operations lean_bitmap_aops = {
	.writepage = lean_write_bitmap_page,
	.readpage = lean_read_bitmap_page,
	.writepages = lean_write_bitmap_pages,
	.readpages = lean_read_bitmap_pages
};

void __lean_bitmap_put(struct lean_bitmap *bitmap, int count)
{
	int i;
	struct page *page;

	for (i = 0; i < count; i++) {
		page = bitmap->pages[i];
		put_page(page);
	}
}

struct lean_bitmap *lean_bitmap_get(struct super_block *s, uint64_t band)
{
	int i;
	struct lean_sb_info *sbi = s->s_fs_info;
	struct lean_bitmap *bitmap = LEAN_BITMAP(sbi, band);
	struct address_space *mapping = sbi->bitmap->i_mapping;
	struct page *page;
	unsigned int nr_pages = LEAN_BITMAP_PAGES(sbi);
	pgoff_t off = (band * sbi->bitmap_size * LEAN_SEC) >> PAGE_SHIFT;
	bitmap->off = (band * sbi->bitmap_size * LEAN_SEC) & ~PAGE_MASK;

	for (i = 0; i < nr_pages; i++) {
		page = read_mapping_page(mapping, off + i, NULL);
		if (IS_ERR(page))
			goto free_pages;
	
		BUG_ON(!(bitmap->pages[i] == NULL || bitmap->pages[i] == page));
		bitmap->pages[i] = page;
	}
	return bitmap;
free_pages:
	__lean_bitmap_put(bitmap, i);
	return ERR_CAST(page);
}

/*
 * Populates bitmap->size
 * returns 0 on success
 */
int lean_bitmap_getfree(struct super_block *s, struct lean_bitmap *bitmap)
{
	int err, i;
	struct page *page;
	struct lean_sb_info *sbi = s->s_fs_info;
	uint32_t used = 0;
	long *addr;
	uint64_t off = bitmap->off;
	
	/* size should never be returned to an uninitialized state,
	 * so we can safely check against it without the lock
	 */
	if (bitmap->free != U32_MAX)
		return 0;

	err = mutex_lock_interruptible(&bitmap->lock);
	if (err)
		return err;

	/* Check to see no one has updated the size while we've been waiting */
	if (bitmap->free != U32_MAX)
		return 0;

	for (i = 0; i < LEAN_BITMAP_PAGES(sbi); i++, off = 0) {
		page = bitmap->pages[i];
		if (!page)
			return -EINVAL;

		addr = kmap(page);
		while (off < PAGE_SIZE && off < bitmap->off + LEAN_BITMAP_SIZE(sbi))
			used += hweight_long(*(addr + off++));
		kunmap(page);
	}
	
	bitmap->free = sbi->band_sectors - used;
	mutex_unlock(&bitmap->lock);
	return 0;
}

int lean_bitmap_cache_init(struct super_block *s)
{
	int i;
	struct lean_bitmap *bitmap;
	struct lean_sb_info *sbi = s->s_fs_info;

	/* Allocate an array to hold the bitmap
	 * Each lean_bitmap has an array of pages on the end
	 */
	sbi->bitmap_cache = kcalloc(sbi->band_count, LEAN_BITMAP_SIZE(sbi),
		GFP_KERNEL);
	if (!sbi->bitmap_cache)
		return -ENOMEM;

	for (i = 0; i < sbi->band_count; i ++) {
		bitmap = LEAN_BITMAP(sbi, i);
		mutex_init(&bitmap->lock);
		bitmap->free = U32_MAX;
	}

	sbi->bitmap = new_inode(s);
	if (!sbi->bitmap)
		goto error;
	sbi->bitmap->i_flags = S_PRIVATE;
	set_nlink(sbi->bitmap, 1);
	sbi->bitmap->i_size = sbi->sectors_total >> 3;
	sbi->bitmap->i_blocks = sbi->sectors_total >> 12;
	sbi->bitmap->i_mapping->a_ops = &lean_bitmap_aops;
	mapping_set_gfp_mask(sbi->bitmap->i_mapping, GFP_NOFS);

	return 0;

error:
	kfree(sbi->bitmap_cache);
	return -ENOMEM;
}

void lean_bitmap_cache_destroy(struct super_block *s)
{
	struct lean_sb_info *sbi = s->s_fs_info;

	iput(sbi->bitmap);
	kfree(sbi->bitmap_cache);
}
