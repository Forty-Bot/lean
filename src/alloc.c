#include "driver.h"
#include "lean.h"

#include <linux/buffer_head.h>
#include <linux/blkdev.h>
#include <linux/mpage.h>
#include <linux/mutex.h>
#include <linux/pagemap.h>
#include <linux/slab.h>

/* 
 * The LEAN filesystem stores block allocation data as a bitmap which is divided
 * spatially on disk into groups of sectors called "bands." This structure is
 * defined on-disk by the fields log2_band_sectors and bitmap_start in the
 * superblock, and is represented in-memory by the lean_sb_info.bitmap inode.
 * Our block allocation strategy revolves around allocating sectors for inodes
 * in the same directory in the same band (and sectors for inodes from different
 * directories in different bands). Because of this (and also to reflect the
 * physical grouping of bitmap sectors), the bitmap is accessed through the
 * lean_bitmap structure. 
 *
 * The lean_bitmap structure is used to keep track of the pages mapped to the
 * blocks which make up the band bitmap it represents. All lean_bitmaps are
 * allocated at mount time and stored as an array pointed to by
 * sbi.bitmap_cache. They are accessed with lean_bitmap_get and lean_bitmap_put,
 * which ensure the structures are initialized and the pages are
 * reference-counted. Data modification (but not access) is protected by the 
 * `lock` field. As iterating over a lean_bitmap is a bit of a hairy process,
 * the preferred method is to call lean_bitmap_iterate with a suitable callback.
 * If it is necessary to modify the bitmap data during this loop, pass the
 * lean_bitmap as part of the private data parameter, in order to grab the lock.
 * The `free` field must never be read directly, but instead accessed through
 * the lean_bitmap_getfree function.
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
				  struct address_space *mapping,
				  struct list_head *pages,
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
		if (!page || IS_ERR(page))
			goto free_pages;

		BUG_ON(bitmap->pages[i] && bitmap->pages[i] != page);
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
 *	int page_nr -- The page index in bitmap->pages[]
 *	void *priv -- Private data
 * a non-zero return value will stop iteration early and return that value
 * TODO: Add support for starting at any page
 */
static int lean_bitmap_iterate(struct lean_bitmap *bitmap,
			       int (*func)(char *, uint32_t, int, void *),
			       void *priv)
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
		/* A null page means this bitmap wasn't acquired with
		 * lean_bitmap_get properly
		 * TODO: Remount read-only and WARN instead
		 */
		BUG_ON(!page);

		addr = kmap(page);
		ret = func(addr + off, min_t(uint32_t, limit, PAGE_SIZE) - off,
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
	struct lean_bitmap *bitmap;
	uint32_t count;
	uint32_t sector;
	bool sync;
	/* Bit offset */
	uint8_t off;
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

	pr_info("addr = %p size = %u, off = %u", addr, size, tmp);

	/* If we have an offset, go straight to the bitwise search */
	if (tmp)
		goto retry;

	ptr = (char *)memscan(addr, 0, size);
	pr_info("Searching for a free byte... got %p", ptr);
	if (ptr < addr + size) {
		tmp = (ptr - addr) * 8;
		goto found;
	}

	/*
	 * Skip the byte search on retry, since we either found a full byte
	 * previously (and thus should retry with a bitwise search), or we found
	 * the sector using a bitwise search in the first place
	 * TODO: should we continue with a byte-wise search anyway? It could
	 * help keep down fragmentation.
	 */
retry:
	tmp = find_next_zero_bit((unsigned long *)addr, size, tmp);
	pr_info("Searching for a free bit... got %d", tmp);
	if (tmp < size * 8)
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
	write_one_page(page, data->sync);
	return i;
}

/*
 * Try to allocate a sector within a band. Start at the goal, but search the
 * entire band if necessary
 * TODO: Maybe start the second loop at the goal's page?
 * Takes bitmap->lock
 */
static uint32_t lean_try_alloc(struct super_block *s,
			       struct lean_bitmap *bitmap,
			       uint32_t goal, uint32_t *count)
{
	int found = 0;
	int goal_page_nr = goal >> PAGE_SHIFT;
	struct page *goal_page = bitmap->pages[goal_page_nr];
	char *addr = kmap(goal_page);
	struct lean_try_alloc_data priv = {
		.bitmap = bitmap,
		.count = *count,
		.off = goal & 7,
		.sync = s->s_flags & MS_SYNCHRONOUS
	};

	/* Try searching starting from the goal */
	found = lean_try_alloc_iter((goal >> 3) + addr + bitmap->off,
				    bitmap->len
					- goal_page_nr * PAGE_SIZE
					- (goal >> 3),
				    goal_page_nr, &priv);
	if (found) {
		goal = priv.sector + (goal & ~7);
		goto out;
	}

	/* Search the whole band */
	priv.off = 0;
	found = lean_bitmap_iterate(bitmap, lean_try_alloc_iter, &priv);
	if (found) {
		goal = priv.sector;
		goto out;
	}

	/* No luck */
	goal = 0;

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

	if (goal <= sbi->root || goal > sbi->sectors_total)
		goal = sbi->root;
	band = goal >> sbi->log2_band_sectors;
	band_tgt = goal & (sbi->band_sectors - 1);

	for (i = 0; i < sbi->band_count; i++, band++) {
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

		lean_msg(s, KERN_DEBUG,
			 "trying to allocate %u blocks in band %llu with goal block %u",
			 *count, band, band_tgt);
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

	ret = alloc + band * sbi->band_sectors;

	/* We don't free sectors if there's an error here, since something has
	 * already gone horribly wrong, so we should try not to screw it up
	 * further
	 * TODO: remount read-only
	 */
	if (alloc < sbi->bitmap_size) {
		lean_msg(s, KERN_ERR,
			 "allocated %u blocks at sector %llu, part of band %llu's bitmap",
			 *count, ret, band);
		*errp = -EIO;
		goto err;
	}
	if (ret + *count > sbi->sectors_total || ret <= sbi->root) {
		lean_msg(s, KERN_ERR,
			 "allocated %u blocks at sector %llu, outside the data zone",
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

uint64_t lean_new_zeroed_sectors(struct super_block *s, uint64_t goal,
				 uint32_t *count, int *errp)
{
	uint64_t sector = lean_new_sectors(s, goal, count, errp);
	
	if (*errp) {
		lean_msg(s, KERN_INFO, "failed to allocate sectors");
		return 0;
	}

	/* Take a page from ext4's book here */
	clean_bdev_aliases(s->s_bdev, sector, *count);
	*errp = blkdev_issue_zeroout(s->s_bdev, sector, *count, GFP_NOFS, 0);
	if (*errp) {
		lean_msg(s, KERN_INFO, "failed to zero sectors");
		lean_free_sectors(s, sector, *count);
	}
	return sector;
}

struct lean_free_sectors_data {
	struct lean_bitmap *bitmap;
	uint32_t start;
	uint32_t count;
	bool sync;
};

static int lean_free_sectors_iter(char *addr, uint32_t len, int page_nr,
				  void *priv)
{
	int i;
	struct lean_free_sectors_data *data = priv;
	struct page *page = data->bitmap->pages[page_nr];

	for (i = 0; i < data->count && data->start + i < len * 8; i++) {
		if (!lean_clear_bit_atomic(&data->bitmap->lock,
					   data->start + i, addr)) {
			/*
			 * Double free error! Store the offending sector in
			 * data->start for later retrieval. We still need to
			 * update count to keep bitmap->free accurate
			 */
			data->start = data->start + i + page_nr * PAGE_SIZE;
			data->count -= i;
			return -EINVAL;
		}
	}

	lock_page(page);
	set_page_dirty(page);
	write_one_page(page, data->sync);

	data->start -= len * 8;
	data->count -= i;

	return !data->count;
}

void lean_free_sectors(struct super_block *s, uint64_t start, uint32_t count)
{
	int err;
	struct lean_bitmap *bitmap;
	struct lean_free_sectors_data data;
	struct lean_sb_info *sbi = (struct lean_sb_info *)s->s_fs_info;
	uint64_t band = start >> sbi->log2_band_sectors;
	uint32_t start_band = start & (sbi->band_sectors - 1);

	if (start <= sbi->root || start + count > sbi->sectors_total) {
		lean_msg(s, KERN_ERR,
			 "attempted to free %u blocks at sector %llu, outside the data zone",
			 count, start);
		return;
	} else if (start_band < sbi->bitmap_size || start_band + count > sbi->band_sectors) {
		lean_msg(s, KERN_ERR,
			 "attempted to free %u blocks at sector %llu, part of the block bitmap",
			 count, start);
		return;
	}

	bitmap = lean_bitmap_get(s, band);
	data.bitmap = bitmap;
	data.start = start_band;
	data.count = count;
	err = lean_bitmap_iterate(bitmap, lean_free_sectors_iter, bitmap);
	if (err == -EINVAL) {
		lean_msg(s, KERN_ERR,
			 "attempted to free already freed block %llu",
			 start + (data.start - start_band));
	} else if (data.count) {
		lean_msg(s, KERN_WARNING,
			 "failed to free %u sectors starting at %llu",
			 data.count, start + (count - data.count));
	}

	spin_lock(&bitmap->lock);
	bitmap->free += data.count;
	spin_unlock(&bitmap->lock);
	percpu_counter_add(&sbi->free_counter, data.count);

	lean_bitmap_put(bitmap);
}
