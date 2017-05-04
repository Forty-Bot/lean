#include "driver.h"
#include "lean.h"

#include <linux/buffer_head.h>
#include <linux/mpage.h>
#include <linux/pagemap.h>

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

	lean_msg(s, KERN_DEBUG,
		"mapping bitmap sector %lu to band %llu and hardware sector %llu",
		sec, band, band_sec);
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

void lean_put_bitmap(struct lean_bitmap *bitmap)
{
	struct page *page;

	for (page = bitmap->first;
		page != NULL;
		page = (struct page *) page->private) {
		pr_debug("lean: freeing page %lu\n", page->index);
		ClearPagePrivate(page);
		kunmap(page);
		put_page(page);
	}
}

struct lean_bitmap *lean_get_bitmap(struct super_block *s, uint64_t band)
{
	int i;
	struct lean_sb_info *sbi = s->s_fs_info;
	struct lean_bitmap *bitmap = &sbi->bitmap_cache[band];
	struct address_space *mapping = sbi->bitmap->i_mapping;
	struct page *page, *prev;
	pgoff_t off = (band * sbi->bitmap_size * LEAN_SEC) >> PAGE_SHIFT;
	unsigned int nr_pages = (sbi->bitmap_size * LEAN_SEC) >> PAGE_SHIFT;

	nr_pages = nr_pages ? nr_pages : 1;
	bitmap->first = NULL;
	prev = NULL;

	lean_msg(s, KERN_DEBUG,
		"Reading %u pages from band %llu starting at page %lu",
		nr_pages, band, off);

	for (i = 0; i < nr_pages; i++) {
		page = read_mapping_page(mapping, off + i, NULL);
		if (IS_ERR(page))
			goto free_pages;
		kmap(page);
		if (i == 0) {
			bitmap->start = page_address(page) + (
				(band * sbi->bitmap_size * LEAN_SEC)
				& ~PAGE_MASK);
		}
		SetPagePrivate(page);
		if (prev == NULL)
			bitmap->first = page;
		else
			prev->private = (unsigned long) page;
		prev = page;
		prev->private = (unsigned long) NULL;
	}
	return bitmap;
free_pages:
	lean_put_bitmap(bitmap);
	return ERR_CAST(page);
}
