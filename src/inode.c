#include "driver.h"
#include "lean.h"

#include <linux/buffer_head.h>
#include <linux/err.h>
#include <linux/fs.h>
#include <linux/mpage.h>
#include <linux/quotaops.h>
#include <linux/random.h>
#include <linux/writeback.h>

/*
 * Find the nth sector in an inode
 * Modifies count on success
 * Must be called with li->lock held
 */
static uint64_t lean_find_sector(struct lean_ino_info *li,
				 uint64_t sec, uint32_t *count)
{
	int i = 0;
	uint64_t extent = li->extent_starts[i];
	uint32_t size = li->extent_sizes[i];

	while (sec > size && i < li->extent_count) {
		extent = li->extent_starts[i];
		size = li->extent_sizes[i];
		sec -= size;
		i++;
	}
	
	if (sec <= size) {
		/* Try to map as many sectors as we can */
		for (i = 1; i < *count && sec + i < size; i++);
		*count = i;
	} else {
		return 0;
	}
	return extent + sec;
}

static int lean_get_block(struct inode *inode, sector_t sec,
			  struct buffer_head *bh_result, int create)
{
	bool new = false;
	int ret;
	struct lean_ino_info *li = LEAN_I(inode);
	uint64_t sector;
	uint32_t count = bh_result->b_size >> inode->i_blkbits;

	lean_msg(inode->i_sb, KERN_DEBUG, "mapping inode %lu sector %lu",
		 inode->i_ino, sec);

	down_read(&li->alloc_lock);
	sector = lean_find_sector(li, sec, &count);
	if (!sector) {
		if (!create) {
			ret = -ENXIO;
			goto out;
		}
		if (li->extent_count == LEAN_INODE_EXTENTS) {
			/* We have no extents left in the inode */
			ret = -EFBIG;
			goto out;
		}

		up_read(&li->alloc_lock);
		down_write(&li->alloc_lock);
		
		/* 
		 * Try again in case someone else has already allocated new
		 * sectors while we were waiting for the write lock
		 */
		sector = lean_find_sector(li, sec, &count);
		if (sector)
			goto found;

		ret = lean_extend_inode(inode, &sector, &count);
		if (ret) {
			up_write(&li->alloc_lock);
			return ret;
		}
		new = true;

found:
		downgrade_write(&li->alloc_lock);
	}

	lean_msg(inode->i_sb, KERN_DEBUG, "mapping %u sector(s) at sector %llu",
		 count, sector);
	map_bh(bh_result, inode->i_sb, sector);
	bh_result->b_size = count << inode->i_blkbits;
	if (new)
		set_buffer_new(bh_result);
	ret = 0;

out:
	up_read(&li->alloc_lock);
	return ret;
}

static int lean_readpage(struct file *file, struct page *page)
{
	return mpage_readpage(page, lean_get_block);
}

static int lean_readpages(struct file *file, struct address_space *mapping,
			  struct list_head *pages, unsigned int nr_pages)
{
	return mpage_readpages(mapping, pages, nr_pages, lean_get_block);
}

static int lean_writepage(struct page *page, struct writeback_control *wbc)
{
	return mpage_writepage(page, lean_get_block, wbc);
}

static int lean_writepages(struct address_space *mapping,
			   struct writeback_control *wbc)
{
	return mpage_writepages(mapping, wbc, lean_get_block);
}

static const struct address_space_operations lean_aops = {
	.readpage = lean_readpage,
	.readpages = lean_readpages,
	.writepage = lean_writepage,
	.writepages = lean_writepages
};

struct inode *lean_iget(struct super_block *s, uint64_t ino)
{
	int ret = -EIO;
	struct buffer_head *bh;
	struct lean_sb_info *sbi = s->s_fs_info;
	struct lean_inode *raw;
	struct lean_ino_info *li;
	struct inode *inode;
	uint32_t attr;

	inode = iget_locked(s, ino);
	if (!inode)
		return ERR_PTR(-ENOMEM);

	/* This inode is cached */
	if (!(inode->i_state & I_NEW))
		return inode;
	li = LEAN_I(inode);

	if (ino < sbi->root || ino > sbi->sectors_total) {
		ret = -EINVAL;
		goto bad_inode;
	}

	bh = sb_bread(s, ino);
	if (!bh)
		goto bad_inode;

	raw = (struct lean_inode *)bh->b_data;
	if (memcmp(raw->magic, LEAN_MAGIC_INODE, sizeof(raw->magic))) {
		brelse(bh);
		ret = -EUCLEAN;
		goto bh_bad_inode;
	}

	if (lean_inode_to_info(raw, li)) {
		brelse(bh);
		ret = -EUCLEAN;
		goto bh_bad_inode;
	}
	brelse(bh);

	if (li->extent_count < 1 || li->extent_count > LEAN_INODE_EXTENTS) {
		lean_msg(s, KERN_WARNING, "corrupt inode %lu", inode->i_ino);
		ret = -EUCLEAN;
		goto bad_inode;
	}

	attr = le32_to_cpu(raw->attr);
	inode->i_mode = attr & LIA_POSIX_MASK;
	if (LIA_ISFMT_REG(attr))
		inode->i_mode |= S_IFREG;
	if (LIA_ISFMT_DIR(attr))
		inode->i_mode |= S_IFDIR;
	if (LIA_ISFMT_SYM(attr))
		inode->i_mode |= S_IFLNK;
	inode->i_flags &= ~(S_SYNC | S_NOATIME | S_IMMUTABLE);
	/* No suid or xattr security attributes */
	inode->i_flags |= S_NOSEC;
	if (ino == sbi->bad)
		inode->i_flags |= S_PRIVATE;
	if (attr & LIA_SYNC)
		inode->i_flags |= S_SYNC;
	if (attr & LIA_NOATIME)
		inode->i_flags |= S_NOATIME;
	if (attr & LIA_IMMUTABLE)
		inode->i_flags |= S_IMMUTABLE;

	i_uid_write(inode, le32_to_cpu(raw->uid));
	i_gid_write(inode, le32_to_cpu(raw->gid));
	set_nlink(inode, le32_to_cpu(raw->link_count));
	inode->i_atime = lean_timespec(le64_to_cpu(raw->time_access));
	inode->i_ctime = lean_timespec(le64_to_cpu(raw->time_status));
	inode->i_mtime = lean_timespec(le64_to_cpu(raw->time_modify));
	inode->i_size = le64_to_cpu(raw->size);
	inode_set_bytes(inode, le64_to_cpu(raw->sector_count) * LEAN_SEC);

	inode->i_mapping->a_ops = &lean_aops;
	if (S_ISREG(inode->i_mode)) {
		inode->i_op = &lean_file_inode_ops;
		inode->i_fop = &lean_file_ops;
	} else {
		inode->i_op = &lean_dir_inode_ops;
		inode->i_fop = &lean_dir_ops;
	}

	init_rwsem(&li->alloc_lock);

	unlock_new_inode(inode);
	return inode;

bh_bad_inode:
	brelse(bh);
bad_inode:
	iget_failed(inode);
	return ERR_PTR(ret);
}

int lean_write_inode(struct inode *inode, struct writeback_control *wbc)
{
	int ret = 0;
	ino_t ino = inode->i_ino;
	struct buffer_head *bh;
	struct super_block *s = inode->i_sb;
	struct lean_sb_info *sbi = s->s_fs_info;
	struct lean_inode *raw;
	struct lean_ino_info *li = LEAN_I(inode);
	uint32_t attr;

	if (ino < sbi->root || ino > sbi->sectors_total)
		return -EINVAL;

	bh = sb_bread(s, ino);
	if (!bh)
		return -EIO;
	raw = (struct lean_inode *)bh->b_data;

	attr = (raw->attr & ~LIA_POSIX_MASK)
		| (inode->i_mode & LIA_POSIX_MASK);
	if (S_ISREG(inode->i_mode))
		attr |= LIA_FMT_REG;
	if (S_ISDIR(inode->i_mode))
		attr |= LIA_FMT_DIR;
	if (S_ISLNK(inode->i_mode))
		attr |= LIA_FMT_SYM;
	attr &= ~(LIA_SYNC | LIA_NOATIME | LIA_IMMUTABLE);
	if (IS_SYNC(inode))
		attr |= LIA_SYNC;
	if (IS_NOATIME(inode))
		attr |= LIA_NOATIME;
	if (IS_IMMUTABLE(inode))
		attr |= LIA_IMMUTABLE;
	raw->attr = cpu_to_le32(attr);

	raw->uid = cpu_to_le32(i_uid_read(inode));
	raw->gid = cpu_to_le32(i_gid_read(inode));
	raw->link_count = cpu_to_le32(inode->i_nlink);
	raw->time_access = cpu_to_le64(lean_time(inode->i_atime));
	raw->time_status = cpu_to_le64(lean_time(inode->i_ctime));
	raw->time_modify = cpu_to_le64(lean_time(inode->i_mtime));
	raw->size = cpu_to_le64(i_size_read(inode));

	down_read(&li->alloc_lock);
	raw->sector_count = cpu_to_le64(inode_get_bytes(inode) >>
					LEAN_SEC_SHIFT);

	lean_info_to_inode(li, raw);
	up_read(&li->alloc_lock);

	mark_buffer_dirty(bh);
	if (wbc->sync_mode == WB_SYNC_ALL) {
		sync_dirty_buffer(bh);
		if (buffer_req(bh) && !buffer_uptodate(bh)) {
			lean_msg(s, KERN_WARNING, "unable to sync inode %lu",
				 ino);
			ret = -EIO;
		}
	}
	brelse(bh);
	return ret;
}

/* A combination of afs_setattr and ext2_setattr for now */
int lean_setattr(struct dentry *de, struct iattr *attr)
{
	int ret;
	struct inode *inode = d_inode(de);

	if (attr->ia_valid & ATTR_SIZE)
		return -EINVAL;

	ret = setattr_prepare(de, attr);
	if (ret)
		return ret;

	setattr_copy(inode, attr);
	mark_inode_dirty(inode);

	return ret;
}

/*
 * This function returns the sector which is immediately after the end
 * of the last extent in an inode
 */
static uint64_t lean_find_next_sector(struct inode *inode)
{
	struct lean_ino_info *li = LEAN_I(inode);

	return li->extent_starts[li->extent_count - 1]
		+ li->extent_sizes[li->extent_count - 1];
}

/*
 * Must be called with LEAN_I(inode)->lock taken for writing
 */
int lean_extend_inode(struct inode *inode, uint64_t *sector, uint32_t *count)
{
	int ret;
	struct lean_ino_info *li = LEAN_I(inode);
	struct super_block *s = inode->i_sb;

	WARN_ON_ONCE(*count > INT_MAX);

	*sector = lean_find_next_sector(inode);
	*sector = lean_new_zeroed_sectors(s, *sector, count, &ret);
	if (ret)
		return ret;

	/*
	 * Don't worry about barriers, as no one should read from li until after
	 * we release the write lock (implying a barrier)
	 */
	if (*sector == li->extent_starts[li->extent_count - 1]
			+ li->extent_sizes[li->extent_count - 1]) {
		li->extent_sizes[li->extent_count - 1] += *count;
	} else {
		/* We need to add another extent */
		if (li->extent_count >= 6) {
			lean_msg(s, KERN_INFO, "cannot create extent");
			lean_free_sectors(s, *sector, *count);
			return -ENXIO;
		}
		li->extent_starts[li->extent_count] = *sector;
		li->extent_sizes[li->extent_count] = *count;
		li->extent_count++;
	}

	inode_add_bytes(inode, *count * LEAN_SEC);
	inode->i_ctime = current_time(inode);
	mark_inode_dirty(inode);
	return ret;
}

/*
 * The following two functions are based off Orlov's allocator, as described in
 * fs/ext2/ialloc.c. Directories are placed in bands with better-than-average
 * free sectors, starting at the band of their parent, or failing that, in the
 * first band with a free sector. Top-level directories start in a random band
 * instead. Ordinary files are placed in the same band as their directory, if
 * possible, a band with free sectors selected by quadratic probing (based on an
 * initial guess based on their directory's inode), or in the first free sector.
 */
static uint64_t lean_find_goal_dir(struct inode *parent)
{
	struct lean_bitmap *bitmap;
	struct super_block *s = parent->i_sb;
	struct lean_sb_info *sbi = (struct lean_sb_info *)s->s_fs_info;
	uint32_t free, i;
	uint32_t mean_free = lean_count_free_sectors(s) / sbi->band_count;  
	uint64_t goal, band;

	if (parent == d_inode(s->s_root))
		goal = (prandom_u32() << 31) + prandom_u32();
	else
		goal = parent->i_ino;
	band = goal % sbi->band_count;

	/* Try to find a band with above-average free sectors */
	for (i = 0; i < sbi->band_count; i++) {
		if (++band > sbi->band_count)
			band -= sbi->band_count;
		
		bitmap = lean_bitmap_get(s, band);
		if (IS_ERR(bitmap))
			continue;

		free = lean_bitmap_getfree(bitmap);
		lean_bitmap_put(bitmap);
		if (free > mean_free)
			return band << sbi->log2_band_sectors;
	}

	/* Couldn't find any better-than-average sectors, just return the goal */
	return goal;
}

static uint64_t lean_find_goal_other(struct inode *parent)
{
	struct super_block *s = parent->i_sb;
	struct lean_sb_info *sbi = (struct lean_sb_info *)s->s_fs_info;
	struct lean_bitmap *bitmap;
	uint32_t free;
	uint64_t i, isquared;
	uint64_t band = parent->i_ino >> sbi->log2_band_sectors;

	/* Default to the parent sector on error or space left in the band */
	bitmap = lean_bitmap_get(s, band);
	if (IS_ERR(bitmap))
		return parent->i_ino;
	
	free = lean_bitmap_getfree(bitmap);
	lean_bitmap_put(bitmap);
	if (free) {
		lean_bitmap_put(bitmap);
		return parent->i_ino;
	}
	lean_bitmap_put(bitmap);

	/*
	 * Try a quadratic search starting at a sector determined by the parent
	 * sector
	 */
	band = parent->i_ino % sbi->band_count;
	for (i = 1, isquared = 1;
	     isquared < sbi->band_count;
	     i += 2, isquared += i) {
		band += i;
		if (band > sbi->band_count)
			band -= sbi->band_count;

		bitmap = lean_bitmap_get(s, band);
		if (IS_ERR(bitmap))
			continue;

		free = lean_bitmap_getfree(bitmap);
		lean_bitmap_put(bitmap);
		if (free)
			return band << sbi->log2_band_sectors;
	}

	/*
	 * We didn't check everything the the quadratic search, so try a linear
	 * search when we allocate the block
	 */
	return parent->i_ino;
}

struct inode *lean_new_inode(struct inode *dir, umode_t mode,
			     const struct qstr *qstr)
{
	int err;
	struct super_block *s = dir->i_sb;
	struct lean_sb_info *sbi = (struct lean_sb_info *)s->s_fs_info;
	struct inode *inode;
	struct lean_ino_info *li;
	struct timespec ts;
	uint32_t count = sbi->prealloc;
	uint64_t sec, goal;

	inode = new_inode(s);
	if (!inode)
		return ERR_PTR(-ENOMEM);
	li = LEAN_I(inode);

	if (S_ISDIR(mode))
		goal = lean_find_goal_dir(dir);
	else
		goal = lean_find_goal_other(dir);

	sec = lean_new_zeroed_sectors(s, goal, &count, &err);
	if (err)
		goto fail;
	
	inode_init_owner(inode, dir, mode);
	inode->i_ino = sec;
	inode->i_size = 0;
	inode_set_bytes(inode, count * LEAN_SEC);
	ts = current_time(inode);
	inode->i_mtime = inode->i_atime = inode->i_ctime = ts;
	li->time_create = lean_time(ts);
	li->extent_count = 1;
	li->indirect_count = 0;
	li->indirect_first = 0;
	li->indirect_last = 0;
	li->fork = 0;
	li->extent_starts[0] = sec;
	li->extent_sizes[0] = count;
	init_rwsem(&li->alloc_lock);

	inode->i_mapping->a_ops = &lean_aops;
	if (S_ISREG(inode->i_mode)) {
		inode->i_op = &lean_file_inode_ops;
		inode->i_fop = &lean_file_ops;
	} else {
		inode->i_op = &lean_dir_inode_ops;
		inode->i_fop = &lean_dir_ops;
	}

	if (insert_inode_locked(inode) < 0) {
		lean_msg(s, KERN_ERR, "inode number %llu already in use", sec);
		err = -EIO;
		goto fail;
	}

	mark_inode_dirty(inode);
	return inode;

fail:
	make_bad_inode(inode);
	iput(inode);
	return ERR_PTR(err);
}
