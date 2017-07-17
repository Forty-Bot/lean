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
		+ sec - (band * sbi->bitmap_size);

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
	unsigned int nr_pages = ((bitmap->len + ~PAGE_MASK) & PAGE_MASK)
		>> PAGE_SHIFT;
	/* Offset in page-sized units */
	pgoff_t off = (band * sbi->bitmap_size * LEAN_SEC) >> PAGE_SHIFT;
	/* Offset from the beginning of the page (in bytes) */
	bitmap->off = (band * sbi->bitmap_size * LEAN_SEC) & ~PAGE_MASK;

	for (i = 0; i < nr_pages; i++) {
		page = read_mapping_page(mapping, off + i, NULL);
		if (IS_ERR(page) || page == NULL)
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
 * Iterate over a bitmap, calling func on each page-sized (or less) chunk
 * func()'s arguments are:
 *	char *addr -- The starting address of this chunk
 *	uint64_t len -- The length of the chunk
 *	void *data -- Private data
 */
static int lean_bitmap_iterate(struct lean_bitmap *bitmap,
	int (*func)(char *, uint64_t, void *), void *data)
{
	int i, ret;
	struct page *page;
	char *addr;
	uint64_t off = bitmap->off;
	uint64_t limit = bitmap->len + off;
	
	for (i = 0, ret = 0;
		i < LEAN_ROUND_PAGE(bitmap->len) >> PAGE_SHIFT && !ret;
		i++, off = 0, limit -= PAGE_SIZE) {
		page = bitmap->pages[i];
		/* A null page means this bitmap wasn't aquired with
		 * lean_bitmap_get peoperly
		 */
		BUG_ON(!page);
		
		addr = kmap(page);
		ret = func(addr + off,
			min(limit, (uint64_t) PAGE_SIZE) - off, data);
		kunmap(page);
	}
	return ret;	
}

static int lean_bitmap_getfree_iter(char *addr, uint64_t len, void *data)
{
	uint32_t *used = data;

	*used += memweight(addr, len);
	return 0;
}

/*
 * Returns the free blocks in a bitmap
 * Always use this and not lean_bitmap->free directly
 * May take bitmap->lock
 */
uint32_t lean_bitmap_getfree(struct lean_bitmap *bitmap)
{
	uint32_t used = 0;
	
	/* size should never be returned to an uninitialized state,
	 * so we can safely check against it without the lock
	 */
	if (bitmap->free != U32_MAX)
		return bitmap->free;

	spin_lock(&bitmap->lock);

	/* Check to see no one has updated the size while we've been waiting */
	if (bitmap->free != U32_MAX) {
		spin_unlock(&bitmap->lock);
		return bitmap->free;
	}

	lean_bitmap_iterate(bitmap, lean_bitmap_getfree_iter, &used);
	bitmap->free = (bitmap->len << 3) - used;
	spin_unlock(&bitmap->lock);
	return bitmap->free;
}

/*
 * Initialize the bitmap inode and bitmap_cache fields
 * along with associated info
 */
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

	for (i = 0; i < sbi->band_count; i++) {
		bitmap = LEAN_BITMAP(sbi, i);
		spin_lock_init(&bitmap->lock);
		bitmap->free = U32_MAX;
		if (likely(i + 1 < sbi->band_count))
			bitmap->len = sbi->band_sectors >> 3;
		else
			/* The last bitmap may be cut short */
			bitmap->len = (sbi->sectors_total
				- i * sbi->band_sectors) >> 3;
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

/*
 * May take lean_bitmap->lock(s)
 */
uint64_t lean_count_free_sectors(struct super_block *s)
{
	int i;
	struct lean_bitmap *bitmap;
	struct lean_sb_info *sbi = s->s_fs_info;
	uint64_t count = 0;

#ifdef LEAN_TESTING
	for (i = 0; i < sbi->band_count; i++) {
		bitmap = lean_bitmap_get(s, i);
		if (IS_ERR(bitmap)) {
			lean_msg(s, KERN_WARNING,
				"could not read band %d bitmap", i);
			continue;
		}
		count += lean_bitmap_getfree(bitmap);
		lean_bitmap_put(bitmap);
	}
	lean_msg(s, KERN_DEBUG, "sbi->sectors_free = %llu, counted = %llu",
		sbi->sectors_free, count);
	return count;
#else /* LEAN_TESTING */
	return percpu_counter_read_positive(&sbi->free_counter);
#endif
}
