#include "driver.h"
#include "lean.h"

#include <linux/buffer_head.h>
#include <linux/err.h>
#include <linux/fs.h>
#include <linux/mpage.h>
#include <linux/writeback.h>

static int lean_get_block(struct inode *inode, sector_t sec, \
	struct buffer_head *bh_result, int create)
{
	int i = 0;
	struct lean_ino_info *li = LEAN_I(inode);
	uint64_t extent = li->extent_starts[i];
	uint32_t size = li->extent_sizes[i];

	if(sec > li->sector_count)
		return -ENOSPC;
	while (sec > size && i < LEAN_INODE_EXTENTS) {
		extent = li->extent_starts[i];
		size = li->extent_sizes[i];
		sec -= size;
		i++;
	}
	/* Double check to ensure consistency */
	if (i == LEAN_INODE_EXTENTS)
		return -ENOSPC;

	map_bh(bh_result, inode->i_sb, extent + sec);
	return 0;
}

static int lean_readpage(struct file *file, struct page *page)
{
	return mpage_readpage(page, lean_get_block);
}

static int lean_readpages(struct file *file, struct address_space *mapping,
	struct list_head *pages, unsigned nr_pages)
{
	return mpage_readpages(mapping, pages, nr_pages, lean_get_block);
}

const struct address_space_operations lean_aops = {
	.readpage = lean_readpage,
	.readpages = lean_readpages
};

struct inode *lean_iget(struct super_block *s, uint64_t ino)
{
	int ret = -EIO;
	struct buffer_head *bh;
	struct lean_sb_info *sbi = s->s_fs_info;
	struct lean_inode *raw;
	struct lean_ino_info *li;
	struct inode *inode;

	inode = iget_locked(s, ino);
	if (!inode) {
		return ERR_PTR(-ENOMEM);
	}
	/* This inode is cached */
	if (!(inode->i_state & I_NEW))
		return inode;
	li = LEAN_I(inode);
	
	if (ino < sbi->root || ino > sbi->sectors_total) {
		ret = -EINVAL;
		goto bad_inode;
	}
	
	if (!(bh = sb_bread(s, ino)))
		goto bad_inode;
	
	raw = (struct lean_inode *) bh->b_data;
	if (memcmp(raw->magic, LEAN_MAGIC_INODE, sizeof(raw->magic))) {
		brelse(bh);
		ret = -EUCLEAN;
		goto bad_inode;
	}

	if (lean_inode_to_info(raw, li)) {
		brelse(bh);
		ret = -EUCLEAN;
		goto bad_inode;
	}

	brelse(bh);
	
	inode->i_mode = li->attr & LIA_POSIX_MASK;
	if (LIA_ISFMT_REG(li->attr))
		inode->i_mode |= S_IFREG;
	if (LIA_ISFMT_DIR(li->attr))
		inode->i_mode |= S_IFDIR;
	if (LIA_ISFMT_SYM(li->attr))
		inode->i_mode |= S_IFLNK;
	inode->i_flags &= ~(S_SYNC | S_NOATIME | S_IMMUTABLE);
	/* No suid or xattr security attributes */
	inode->i_flags |= S_NOSEC;
	if (ino == sbi->bad)
		inode->i_flags |= S_PRIVATE;
	if (li->attr & LIA_SYNC)
		inode->i_flags |= S_SYNC;
	if (li->attr & LIA_NOATIME)
		inode->i_flags |= S_NOATIME;
	if (li->attr & LIA_IMMUTABLE)
		inode->i_flags |= S_IMMUTABLE;

	i_uid_write(inode, li->uid);
	i_gid_write(inode, li->gid);
	set_nlink(inode, li->link_count);
	inode->i_atime = lean_timespec(li->time_access);
	inode->i_ctime = lean_timespec(li->time_create);
	inode->i_mtime = lean_timespec(li->time_modify);
	inode->i_size = li->size;
	inode->i_blocks = li->sector_count;
	
	inode->i_mapping->a_ops = &lean_aops;
	if (S_ISREG(inode->i_mode)) {
		inode->i_fop = &lean_file_ops;
	} else {
		inode->i_op = &lean_dir_inode_ops;
		inode->i_fop = &lean_dir_ops;
	}

	unlock_new_inode(inode);
	return inode;

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

	if (ino < sbi->root || ino > sbi->sectors_total)
		return -EINVAL;
	
	li->attr = (li->attr & ~LIA_POSIX_MASK)
		| (inode->i_mode & LIA_POSIX_MASK);
	if (S_ISREG(inode->i_mode))
		li->attr |= LIA_FMT_REG;
	if (S_ISDIR(inode->i_mode))
		li->attr |= LIA_FMT_DIR;
	if (S_ISLNK(inode->i_mode))
		li->attr |= LIA_FMT_SYM;
	li->attr &= (LIA_SYNC | LIA_NOATIME | LIA_IMMUTABLE);
	if (IS_SYNC(inode))
		li->attr |= LIA_SYNC;
	if (IS_NOATIME(inode))
		li->attr |= LIA_NOATIME;
	if (IS_IMMUTABLE(inode))
		li->attr |= LIA_IMMUTABLE;

	i_uid_write(inode, li->uid);
	i_gid_write(inode, li->gid);
	li->link_count = inode->i_nlink;
	li->time_access = lean_time(inode->i_atime);
	li->time_create = lean_time(inode->i_ctime);
	li->time_modify = lean_time(inode->i_mtime);
	li->size = inode->i_size;
	li->sector_count = inode->i_blocks;
	
	if (!(bh = sb_bread(s, ino)))
		return -EIO;
	
	raw = (struct lean_inode *) bh->b_data;
	lean_info_to_inode(li, raw);
	mark_buffer_dirty(bh);
	if (wbc->sync_mode == WB_SYNC_ALL) {
		sync_dirty_buffer(bh);
		if (buffer_req(bh) && !buffer_uptodate(bh)) {
			pr_warn("lean: unable to sync inode %lu", ino);
			ret = -EIO;
		}
	}
	brelse(bh);
	return ret;
}
