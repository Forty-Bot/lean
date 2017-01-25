#include "driver.h"
#include "lean.h"

#include <linux/buffer_head.h>
#include <linux/err.h>
#include <linux/fs.h>

struct inode *lean_iget(struct super_block *s, uint64_t ino)
{
	int ret = -EIO;
	struct buffer_head *bh;
	struct lean_sb_info *sbi = s->s_fs_info;
	struct lean_inode *raw;
	struct lean_ino_info *li;
	struct inode *inode;

	inode = iget_locked(s, ino);
	if(!inode) {
		return ERR_PTR(-ENOMEM);
	}
	/* This inode is cached */
	if(!(inode->i_state & I_NEW))
		return inode;
	li = LEAN_I(inode);
	
	if(ino < sbi->root || ino > sbi->sectors_total) {
		ret = -EINVAL;
		goto bad_inode;
	}
	
	if(!(bh = sb_bread(s, ino))) {
		goto bad_inode;
	}
	
	raw = (struct lean_inode *) bh->b_data;
	if(memcmp(raw->magic, LEAN_MAGIC_INODE, sizeof(raw->magic))) {
		brelse(bh);
		ret = -EUCLEAN;
		goto bad_inode;
	}

	if(lean_inode_to_info(raw, LEAN_I(inode))) {
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
	
	/* TODO: set inode_operations */
	brelse(bh);
	
	inode->i_flags &= ~(S_SYNC | S_NOATIME | S_IMMUTABLE);
	if(ino == sbi->bad)
		inode->i_flags |= S_PRIVATE;
	if(li->attr & LIA_SYNC)
		inode->i_flags |= S_SYNC;
	if(li->attr & LIA_NOATIME)
		inode->i_flags |= S_NOATIME;
	if(li->attr & LIA_IMMUTABLE)
		inode->i_flags |= S_IMMUTABLE;
	
	unlock_new_inode(inode);
	return inode;

bad_inode:
	iget_failed(inode);
	return ERR_PTR(ret);
}
