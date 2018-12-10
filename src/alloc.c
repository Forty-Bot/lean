#include "kernel.h"
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

static const struct address_space_operations lean_bitmap_aops = {
	.writepage = lean_write_bitmap_page,
	.readpage = lean_read_bitmap_page,
	.writepages = lean_write_bitmap_pages,
	.readpages = lean_read_bitmap_pages,
	.set_page_dirty = lean_set_page_dirty,
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

		WARN_ON(bitmap->pages[i] && bitmap->pages[i] != page);
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
static int _lean_bitmap_iterate(struct lean_bitmap *bitmap,
				int (*func)(char *, uint32_t, int, void *),
				void *priv, bool atomic)
{
	int i, ret;
	char *addr;
	uint32_t off = bitmap->off;
	uint32_t limit = bitmap->len + off;

	for (i = 0, ret = 0;
	     i < LEAN_ROUND_PAGE(bitmap->len) >> PAGE_SHIFT && !ret;
	     i++, off = 0, limit -= PAGE_SIZE) {
		struct page *page = bitmap->pages[i];
		/* A null page means this bitmap wasn't acquired with
		 * lean_bitmap_get properly
		 * TODO: Remount read-only and WARN instead
		 */
		BUG_ON(!page);

		if (atomic)
			addr = kmap_atomic(page);
		else
			addr = kmap(page);

		ret = func(addr + off, min_t(uint32_t, limit, PAGE_SIZE) - off,
			   i, priv);

		if (atomic)
			kunmap_atomic(addr);
		else
			kunmap(page);
	}
	return ret;
}

#define lean_bitmap_iterate(bitmap, func, priv) \
	_lean_bitmap_iterate(bitmap, func, priv, false)
#define lean_bitmap_iterate_atomic(bitmap, func, priv) \
	_lean_bitmap_iterate(bitmap, func, priv, true)

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

	/* We need to use _atomic since we hold the spinlock */
	lean_bitmap_iterate_atomic(bitmap, lean_bitmap_getfree_iter, &used);
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
	/* Use the superblock as this inode's ino
	 * We need one as a hash value
	 */
	sbi->bitmap->i_ino = sbi->super_primary;
	sbi->bitmap->i_flags = S_PRIVATE;
	set_nlink(sbi->bitmap, 1);
	sbi->bitmap->i_size = sbi->sectors_total >> 3;
	sbi->bitmap->i_blocks = sbi->sectors_total >> 12;
	LEAN_I(sbi->bitmap)->extra = NULL;
	sbi->bitmap->i_mapping->a_ops = &lean_bitmap_aops;
	mapping_set_gfp_mask(sbi->bitmap->i_mapping, GFP_NOFS);
	insert_inode_hash(sbi->bitmap);

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
	struct lean_sb_info *sbi = s->s_fs_info;
#ifdef LEAN_TESTING
	int i;
	uint64_t count = 0;
	
	for (i = 0; i < sbi->band_count; i++) {
		struct lean_bitmap *bitmap = lean_bitmap_get(s, i);

		if (IS_ERR(bitmap)) {
			lean_msg(s, KERN_WARNING,
				 "could not read band %d bitmap", i);
			continue;
		}
		count += lean_bitmap_getfree(bitmap);
		lean_bitmap_put(bitmap);
	}
	return count;
#else /* LEAN_TESTING */
	return percpu_counter_read_positive(&sbi->free_counter);
#endif
}

struct lean_try_alloc_data {
	struct lean_bitmap *bitmap;
	int err;
	uint32_t count;
	uint32_t sector;
	bool sync;
	/* Bit offset */
	uint8_t off;
};

enum lean_try_alloc_state {
	LTAS_GREEDY, /* Assume there is a free bit very near where we start
			searching, but not necessarily a full byte */
	LTAS_BYTEWISE, /* Search for a free byte */
	LTAS_BITWISE, /* Search for a free bit */
	LTAS_FOUND_BYTE,
	LTAS_FOUND_BIT,
	LTAS_FOUND_GREEDY,
	LTAS_ACQUIRED,
};

/*
 * This iterator tries to find the first free byte of sectors and then any free
 * sector. It then allocates the sector, if possible, or returns to searching.
 * After allocating a sector, it attempts to allocate up to data->num sectors.
 * It returns the number of sectors allocated, and stores the first sector
 * (relative to he start of the band) in data->sector
 *
 * We use a lean_try_alloc_state enum to implement a state machine for the
 * search. Valid state transitions are:
 *
 * Current State     -> Next State        | Comment
 * ---------------------------------------+-------------------------------------
 * LTAS_GREEDY       -> LTAS_FOUND_GREEDY |
 * LTAS_GREEDY       -> return            | We searched the entire band and
 *                                        | found no free sectors, so we're done
 * LTAS_FOUND_GREEDY -> LTAS_BYTEWISE     | If someone else took the sector,
 *                                        | they likely took adjacent sectors as
 *                                        | well. Try searching bytewise
 *                                        | instead, as our greedy assumptions
 *                                        | are no longer valid
 * LTAS_FOUND_GREEDY -> LTAS_ACQUIRED     |
 * LTAS_BYTEWISE     -> LTAS_FOUND_BYTE   |
 * LTAS_BYTEWISE     -> LTAS_BITWISE      | There may only be sub-byte (or
 *                                        | unaligned) segments of free sectors
 *                                        | left
 * LTAS_FOUND_BYTE   -> LTAS_BYTEWISE     |
 * LTAS_FOUND_BYTE   -> LTAS_ACQUIRED     |
 * LTAS_BITWISE      -> LTAS_FOUND_BIT    |
 * LTAS_BITWISE      -> return            | If a bitwise search yields nothing,
 *                                        | we have completed our search
 * LTAS_FOUND_BIT    -> LTAS_BITWISE      |
 * LTAS_FOUND_BIT    -> LTAS_ACQUIRED     |
 * LTAS_ACQUIRED     -> rest of function  | Complete the allocation process
 *
 * Takes data->bitmap->lock
 */
static int lean_try_alloc_iter(char *addr, uint32_t size, int page_nr,
			       void *priv)
{
	char *ptr;
	enum lean_try_alloc_state state = LTAS_BYTEWISE;
	int i, retries;
	struct lean_try_alloc_data *data = priv;
	struct page *page = data->bitmap->pages[page_nr];
	int tmp = data->off;

	lean_debug(NULL, "addr = %p size = %u, off = %u", addr, size, tmp);

	/* If we have an offset, go straight to the greedy bitwise search */
	if (tmp)
		state = LTAS_GREEDY;

	while (state != LTAS_ACQUIRED) {
		switch (state) {
		case (LTAS_BYTEWISE):
			ptr = (char *)memscan(addr + (tmp >> 3), 0, size);
			lean_debug(NULL, "Searching for a free byte... got %p",
				   ptr);
			if (ptr < addr + size) {
				tmp = (ptr - addr) * 8;
				state = LTAS_FOUND_BYTE;
				break;
			}
			tmp = data->off;
			state = LTAS_BITWISE;
			break;
		case (LTAS_GREEDY):
		case (LTAS_BITWISE):
			tmp = find_next_zero_bit((unsigned long *)addr,
						 size * 8, tmp);
			lean_debug(NULL, "Searching for a free bit... got %d",
				   tmp);
			if (tmp < size * 8) {
				if (state == LTAS_GREEDY)
					state = LTAS_FOUND_GREEDY;
				else
					state = LTAS_FOUND_BIT;
				break;
			} else {
				return 0;
			}
		case (LTAS_FOUND_GREEDY):
		case (LTAS_FOUND_BYTE):
		case (LTAS_FOUND_BIT):
			if (lean_set_bit_atomic(&data->bitmap->lock,
						tmp, addr)) {
				/* We did not get the sector */
				if (state == LTAS_FOUND_BYTE ||
				    state == LTAS_FOUND_GREEDY)
					state = LTAS_BYTEWISE;
				else
					state = LTAS_BITWISE;
			} else {
				state = LTAS_ACQUIRED;
			}
		case (LTAS_ACQUIRED):
			break;
		}
	}

	data->sector = tmp + page_nr * PAGE_SHIFT;
	for (i = 1; i < data->count; i++)
		if (lean_set_bit_atomic(&data->bitmap->lock, tmp + i, addr))
			break;

	lock_page(page);
	/* XXX: set_page_dirty returns whether the page is newly dirty */
	set_page_dirty(page);

	retries = 0;
	do {
		if (retries)
			lean_debug(NULL, "writing bitmap page: retry %d",
				   retries);
		data->err = lean_write_page(page, data->sync);
		retries++;
	} while (data->err == -EAGAIN && retries <= 4);

	if (data->err) {
		pr_warn("lean: could not write bitmap page: i = %d tmp = %d addr = %p",
			i, tmp, addr);
		for (; i > 0; i--)
			WARN_ON_ONCE(!lean_clear_bit_atomic(&data->bitmap->lock,
							    tmp + i - 1, addr));
		unlock_page(page);
	}

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
			       uint32_t goal, uint32_t *count, int *errp)
{
	int found = 0;
	int goal_page_nr = goal >> PAGE_SHIFT;
	struct page *goal_page = bitmap->pages[goal_page_nr];
	char *addr = kmap(goal_page);
	struct lean_try_alloc_data priv = {
		.bitmap = bitmap,
		.err = 0,
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
	if (priv.err) {
		goto err;
	} else if (found) {
		goal = priv.sector + (goal & ~7);
		goto out;
	}

	/* Search the whole band */
	priv.off = 0;
	found = lean_bitmap_iterate(bitmap, lean_try_alloc_iter, &priv);
	if (priv.err) {
		goto err;
	} else if (found) {
		goal = priv.sector;
		goto out;
	}

	/* No luck */
err:
	goal = 0;
	found = 0;
out:
	kunmap(goal_page);
	*count = found;
	*errp = priv.err;
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

		lean_debug(s,
			   "trying to allocate %u blocks in band %llu with goal block %u",
			   *count, band, band_tgt);
		alloc = lean_try_alloc(s, bitmap, band_tgt, count, errp);
		if (alloc)
			break;

		lean_bitmap_put(bitmap);
		band_tgt = 0;
		if (*errp)
			return 0;
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
		lean_msg(s, KERN_WARNING, "failed to zero sectors");
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
	if (lean_write_page(page, data->sync)) {
		unlock_page(page);
		pr_warn("lean: could not write bitmap page");
	}

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
	} else if (start_band < sbi->bitmap_size ||
		   start_band + count > sbi->band_sectors) {
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
