#include "driver.h"
#include "lean.h"

#include <linux/buffer_head.h>
#include <linux/err.h>
#include <linux/fs.h>
#include <linux/mpage.h>

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

	inode->i_mode = LEAN_M(li->attr);
	i_uid_write(inode, li->uid);
	i_gid_write(inode, li->gid);
	set_nlink(inode, li->link_count);
	inode->i_size = li->size;
	inode->i_atime.tv_sec = li->time_access / 1000000;
	inode->i_atime.tv_nsec = li->time_access * 1000;
	inode->i_ctime.tv_sec = li->time_create / 1000000;
	inode->i_ctime.tv_nsec = li->time_create * 1000;
	inode->i_mtime.tv_sec = li->time_modify / 1000000;
	inode->i_mtime.tv_nsec = li->time_modify * 1000;
	inode->i_size = li->size;
	inode->i_blocks = li->sector_count;
	
	brelse(bh);
	
	inode->i_mapping->a_ops = &lean_aops;
	if (S_ISREG(inode->i_mode)) {
		inode->i_fop = &lean_file_ops;
	} else {
		inode->i_op = &lean_dir_inode_ops;
		inode->i_fop = &lean_dir_ops;
	}

	inode->i_flags &= ~(S_SYNC | S_NOATIME | S_IMMUTABLE);
	if (ino == sbi->bad)
		inode->i_flags |= S_PRIVATE;
	if (li->attr & LIA_SYNC)
		inode->i_flags |= S_SYNC;
	if (li->attr & LIA_NOATIME)
		inode->i_flags |= S_NOATIME;
	if (li->attr & LIA_IMMUTABLE)
		inode->i_flags |= S_IMMUTABLE;
	
	unlock_new_inode(inode);
	return inode;

bad_inode:
	iget_failed(inode);
	return ERR_PTR(ret);
}
