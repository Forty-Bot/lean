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
 *	struct page *page -- The page this chunk came from
 *	void *priv -- Private data
 * its return value determines whether to break out early
 */
static int lean_bitmap_iterate(struct lean_bitmap *bitmap,
	int (*func)(char *, uint32_t, int, void *), void *priv)
{
	int i, ret;
	struct page *page;
	char *addr;
	uint32_t off = bitmap->off;
	uint32_t limit = bitmap->len + off;

	for (i = 0, ret = 0;
		i < LEAN_ROUND_PAGE(bitmap->len) >> PAGE_SHIFT && !ret;
		i++, off = 0, limit -= PAGE_SIZE) {
		page = bitmap->pages[i];
		/* A null page means this bitmap wasn't aquired with
		 * lean_bitmap_get peoperly
		 */
		BUG_ON(!page);

		addr = kmap(page);
		ret = func(addr + off, min(limit, (uint32_t) PAGE_SIZE) - off,
			i, priv);
		kunmap(page);
	}
	return ret;
}

static int lean_bitmap_getfree_iter(char *addr, uint32_t len, int page_nr,
	void *priv)
{
	uint32_t *used = priv;

	*used += memweight(addr, len);
	return false;
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

struct lean_try_alloc_data {
	/* Inputs */
	struct super_block *s;
	struct lean_bitmap *bitmap;
	uint32_t count;
	/* Bit offset */
	uint8_t off;
	/* Outputs */
	uint32_t sector;
};

/*
 * This iterator tries to find the first free byte of sectors and then any free
 * sector. It then allocates the sector, if possible, or returns to a bitwise
 * search. After allocating a sector, it attempts to allocate up to data->num
 * sectors. It returns the number of sectors allocated, and stores the first
 * sector (relative to the start of the band) in data->sector
 * Takes data->bitmap->lock
 */
static int lean_try_alloc_iter(char *addr, uint32_t size, int page_nr,
	void *priv)
{
	int i;
	struct lean_try_alloc_data *data = priv;
	struct page *page = data->bitmap->pages[page_nr];
	int tmp = data->off;
	char *ptr;

	/* If we have an offset, go straight to the bitwise search */
	if (tmp)
		goto retry;

	ptr = (char *) memscan(addr, 0, size);
	if (ptr < addr + size) {
		tmp = (ptr - addr) * 8;
		goto found;
	}

	/*
	 * Skip the byte search on retry, since we either found a full byte
	 * previously (and thus should retry with a bitwise search), or we found
	 * the sector using a bitwise search in the first place
	 */
retry:
	tmp = find_next_zero_bit((unsigned long *) addr, size, tmp);
	if (tmp > size * 8)
		goto found;

	return 0;

found:
	if (lean_set_bit_atomic(&data->bitmap->lock, tmp, addr))
		/* We did not get the sector */
		goto retry;

	data->sector = tmp + page_nr * PAGE_SHIFT;
	for (i = 1; i < data->count; i++)
		if (lean_set_bit_atomic(&data->bitmap->lock, tmp + i, addr))
			break;

	lock_page(page);
	set_page_dirty(page);
	write_one_page(page, priv->s->s_flags & MS_SYNCHRONOUS);
	return i;
}

/*
 * Try to allocate a sector within a band. Start at the goal, but search the
 * entire band if necessary
 * Takes bitmap->lock
 */
static uint32_t lean_try_alloc(struct super_block *s, struct lean_bitmap *bitmap,
	uint32_t goal, uint32_t *count)
{
	int found = 0;
	int goal_page_nr = goal >> PAGE_SHIFT;
	struct page *goal_page = bitmap->pages[goal_page_nr];
	char *addr = kmap(goal_page);
	struct lean_try_alloc_data priv;
	priv.s = s;
	priv.bitmap = bitmap;
	priv.count = *count;
	priv.off = goal & 7;

	/* Try searching starting from the goal */
	found = lean_try_alloc_iter((goal >> 3) + addr + bitmap->off,
		bitmap->len - goal_page_nr * PAGE_SIZE, goal_page_nr, &priv);
	if (found)
		goto iter_found;

	/* Search the whole band */
	priv.off = 0;
	found = lean_bitmap_iterate(bitmap, lean_try_alloc_iter, &priv);
	if (found)
		goto iter_found;

	/* No luck */
	goal = 0;
	goto out;

iter_found:
	goal = priv.sector;
out:
	kunmap(goal_page);
	*count = found;
	return goal;
}

/*
 * Try to allocate new sectors near the goal, or failing that somewhere on the
 * disk. See lean_try_alloc and lean_try_alloc_iter for allocation strategy
 * Takes bitmap->lock(s)
 */
uint64_t lean_new_sectors(struct super_block *s, uint64_t goal, uint32_t *count,
	int *errp)
{
	int i;
	struct lean_bitmap *bitmap;
	struct lean_sb_info *sbi = s->s_fs_info;
	uint32_t band_tgt;
	uint64_t alloc;
	uint64_t band;
	uint64_t ret;

	if (!lean_count_free_sectors(s)) {
		*errp = -ENOSPC;
		return 0;
	}

	if (goal < sbi->root || goal > sbi->sectors_total)
		goal = sbi->root;
	band = goal >> sbi->log2_band_sectors;
	band_tgt = goal & (sbi->band_sectors - 1);

	for (i = 1; i <= sbi->band_count; i++, band++) {
		if (band >= sbi->band_count)
			band = 0;

		bitmap = lean_bitmap_get(s, band);
		if (IS_ERR(bitmap)) {
			*errp = PTR_ERR(bitmap);
			return 0;
		}

		if (!lean_bitmap_getfree(bitmap)) {
			lean_bitmap_put(bitmap);
			continue;
		}

		alloc = lean_try_alloc(s, bitmap, band_tgt, count);
		if (alloc)
			break;

		lean_bitmap_put(bitmap);
		band_tgt = 0;
	}

	if (!alloc) {
		*errp = -ENOSPC;
		return 0;
	}

	ret = band * sbi->band_sectors + alloc;

	/* We don't free sectors if there's an error here, since something has
	 * already gone horribly wrong, so we should try not to screw it up
	 * further
	 * TODO: remount read-only
	 */
	if (alloc < sbi->bitmap_size) {
		lean_msg(s, KERN_ERR,
			"allocated %u blocks at sector %llu, which is part of band %llu's bitmap",
			*count, ret, band);
		*errp = -EIO;
		goto err;
	}
	if (ret > sbi->sectors_total) {
		lean_msg(s, KERN_ERR,
			"allocated %u blocks at sector %llu, which is past the end of the disk",
			*count, ret);
		*errp = -EIO;
		goto err;
	}

	spin_lock(&bitmap->lock);
	bitmap->free -= *count;
	spin_unlock(&bitmap->lock);
	percpu_counter_sub(&sbi->free_counter, *count);

	lean_bitmap_put(bitmap);
	*errp = 0;
	return ret;

err:
	lean_bitmap_put(bitmap);
	return 0;
}
