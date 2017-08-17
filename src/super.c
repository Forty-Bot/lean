#include "driver.h"
#include "lean.h"

#include <linux/backing-dev-defs.h>
#include <linux/buffer_head.h>
#include <linux/err.h>
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/statfs.h>
#include <linux/slab.h>
#include <linux/version.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 13, 0)
#define LEAN_NO_OPTIONS
#endif

/* Taken from fs/ext2/super.c */
void lean_msg(struct super_block *s, const char *prefix, const char *fmt, ...)
{
	struct va_format vaf;
	va_list args;

	va_start(args, fmt);

	vaf.fmt = fmt;
	vaf.va = &args;

	printk("%slean (%s): %pV\n", prefix, s->s_id, &vaf);

	va_end(args);
}

static int lean_statfs(struct dentry *de, struct kstatfs *buf)
{
	struct super_block *s = de->d_sb;
	struct lean_sb_info *sbi = (struct lean_sb_info *)s->s_fs_info;
	uint64_t fsid;

	buf->f_type = (uint32_t)(*LEAN_MAGIC_SUPERBLOCK);
	buf->f_bsize = buf->f_frsize = 512;
	buf->f_blocks = sbi->sectors_total;
	buf->f_bfree = buf->f_bavail = lean_count_free_sectors(s);
	/* We don't have hard inode limits, so don't bother */
	buf->f_files = buf->f_ffree = 0;
	/* Ripped from fs/ext2/super.c */
	fsid = le64_to_cpup((void *)sbi->uuid) ^
	       le64_to_cpup((void *)sbi->uuid + sizeof(uint64_t));
	buf->f_fsid.val[0] = fsid & 0xFFFFFFFFUL;
	buf->f_fsid.val[1] = (fsid >> 32) & 0xFFFFFFFFUL;
	buf->f_namelen = LEAN_DIR_NAME_MAX;
	buf->f_flags = s->s_flags;

#ifdef LEAN_TESTING
	lean_msg(s, KERN_DEBUG, "bs %llu bc %llu bms %llu",
		 sbi->band_sectors, sbi->band_count, sbi->bitmap_size);
#endif /* LEAN_TESTING */

	return 0;
}

/* From fs/ext2/super.c */
static void lean_clear_super_error(struct super_block *s)
{
	struct lean_sb_info *sbi = (struct lean_sb_info *)s->s_fs_info;
	struct buffer_head *sbh = sbi->sbh;
	struct buffer_head *sbh_backup = sbi->sbh_backup;

	if (buffer_write_io_error(sbh)) {
		/*
		 * Oh, dear.  A previous attempt to write the
		 * superblock failed.  This could happen because the
		 * USB device was yanked out.  Or it could happen to
		 * be a transient write error and maybe the block will
		 * be remapped.  Nothing we can do but to retry the
		 * write and hope for the best.
		 */
		lean_msg(s, KERN_ERR,
			 "previous I/O error to superblock detected");
		clear_buffer_write_io_error(sbh);
		set_buffer_uptodate(sbh);
	}
	if (buffer_write_io_error(sbh_backup)) {
		lean_msg(s, KERN_ERR,
			 "previous I/O error to superblock backup detected");
		clear_buffer_write_io_error(sbh_backup);
		set_buffer_uptodate(sbh_backup);
	}
}

/*
 * Updates the buffer_heads representing the superblock and superblock
 * backup and writes them to disk
 * Takes s->s_fs_info->lock
 */
static int lean_sync_super(struct super_block *s, int wait)
{
	int err = 0;
	struct lean_sb_info *sbi = (struct lean_sb_info *)s->s_fs_info;
	struct lean_superblock *sb =
		(struct lean_superblock *)sbi->sbh->b_data;
	struct lean_superblock *sb_backup =
		(struct lean_superblock *)sbi->sbh_backup->b_data;

	lean_clear_super_error(s);

	err = mutex_lock_interruptible(&sbi->lock);
	if (err)
		return err;

	sbi->sectors_free = lean_count_free_sectors(s);
	lean_info_to_superblock(sbi, sb);

	mutex_unlock(&sbi->lock);

	memcpy(sb_backup, sb, sizeof(*sb_backup));
	mark_buffer_dirty(sbi->sbh);
	mark_buffer_dirty(sbi->sbh_backup);
	if (wait) {
		sync_dirty_buffer(sbi->sbh);
		sync_dirty_buffer(sbi->sbh_backup);
		if (buffer_req(sbi->sbh) &&
		    !buffer_uptodate(sbi->sbh)) {
			lean_msg(s, KERN_WARNING,
				 "unable to sync super block");
			err = -EIO;
		}
		if (buffer_req(sbi->sbh_backup) &&
		    !buffer_uptodate(sbi->sbh_backup)) {
			lean_msg(s, KERN_WARNING,
				 "unable to sync super block backup");
			err = -EIO;
		}
	}
	return err;
}

/*
 * Synchonizes the filesystem to disk
 * May take s->s_fs_info->lock
 */
static int lean_sync_fs(struct super_block *s, int wait)
{
	int err;
	struct lean_sb_info *sbi = (struct lean_sb_info *)s->s_fs_info;

	if (sbi->state & LEAN_STATE_CLEAN) {
		err = mutex_lock_interruptible(&sbi->lock);
		if (err)
			return err;
		sbi->state &= ~LEAN_STATE_CLEAN;
		mutex_unlock(&sbi->lock);
	}
	return lean_sync_super(s, wait);
}

/*
 * Synchronizes the filesystem to disk if it is mounted r/w
 * May take s->s_fs_info->lock
 */
int lean_write_super(struct super_block *s)
{
	if (!(s->s_flags & MS_RDONLY))
		return lean_sync_fs(s, true);
	return 0;
}

/*
 * Takes s->s_fs_info->lock if mounted r/w
 */
static void lean_put_super(struct super_block *s)
{
	struct lean_sb_info *sbi = (struct lean_sb_info *)s->s_fs_info;

	if (!(s->s_flags & MS_RDONLY)) {
		if (mutex_lock_interruptible(&sbi->lock)) {
			lean_msg(s, KERN_WARNING, "unable to get super lock");
			goto sync_failed;
		}
		sbi->state |= LEAN_STATE_CLEAN;
		mutex_unlock(&sbi->lock);
		if (lean_sync_super(s, true))
			lean_msg(s, KERN_WARNING, "cannot sync super block");
	}

sync_failed:
	percpu_counter_destroy(&sbi->free_counter);
	lean_bitmap_cache_destroy(s);
	brelse(sbi->sbh);
	if (!(s->s_flags & MS_RDONLY))
		brelse(sbi->sbh_backup);
	s->s_fs_info = NULL;
	kfree(sbi);
}

static struct kmem_cache *lean_inode_cache;

struct inode *lean_inode_alloc(struct super_block *s)
{
	struct lean_ino_info *inode =
		kmem_cache_alloc(lean_inode_cache, GFP_KERNEL);
	if (!inode)
		return NULL;
	return &inode->vfs_inode;
}

static void lean_free_callback(struct rcu_head *head)
{
	struct inode *inode = container_of(head, struct inode, i_rcu);

	kmem_cache_free(lean_inode_cache, LEAN_I(inode));
}

static void lean_inode_free(struct inode *inode)
{
	call_rcu(&inode->i_rcu, lean_free_callback);
}

static void lean_inode_init_once(void *i)
{
	struct lean_ino_info *inode = (struct lean_ino_info *)i;

	inode_init_once(&inode->vfs_inode);
}

static int __init lean_init_inodecache(void)
{
	lean_inode_cache = kmem_cache_create("lean_inode_cache",
					     sizeof(struct lean_ino_info), 0,
					     (SLAB_RECLAIM_ACCOUNT |
					      SLAB_MEM_SPREAD |
					      SLAB_ACCOUNT),
					     lean_inode_init_once);
	if (!lean_inode_cache)
		return -ENOMEM;
	return 0;
}

static void lean_destroy_inodecache(void)
{
	rcu_barrier();
	kmem_cache_destroy(lean_inode_cache);
}

static struct super_operations const lean_super_ops = {
	.alloc_inode = lean_inode_alloc,
	.destroy_inode = lean_inode_free,
	.write_inode = lean_write_inode,
	.put_super = lean_put_super,
	.sync_fs = lean_sync_fs,
	.statfs = lean_statfs,
#ifndef LEAN_NO_OPTIONS
	.show_options = generic_show_options
#endif
};

static int lean_fill_super(struct super_block *s, void *data, int silent)
{
#define lean_msg(s, prefix, fmt, ...) \
	do { \
		if (!silent) { \
			lean_msg(s, prefix, fmt, ##__VA_ARGS__); \
		} \
	} while (0)

	bool found_sb = false;
	int diff;
	int ret = -EINVAL;
	int sec;
	struct buffer_head *bh;
	struct inode *root;
	struct lean_superblock *sb;
	struct lean_sb_info *sbi = kmalloc(sizeof(*sbi), GFP_KERNEL);

	if (!sbi)
		return -ENOMEM;

	if (!sb_set_blocksize(s, 512)) {
		lean_msg(s, KERN_ERR, "cannot set block size to 512");
		goto failure;
	}

	/* Try to read the superblock off sectors 1-32 */
	for (sec = 1; !found_sb && sec <= 32; sec++) {
		bh = sb_bread(s, sec);
		if (!bh) {
			lean_msg(s, KERN_ERR,
				 "unable to read sector %d on dev %s",
				 sec, s->s_id);
			ret = -EIO;
			goto failure;
		} else {
			sb = (struct lean_superblock *)bh->b_data;
			if (!memcmp(sb->magic, LEAN_MAGIC_SUPERBLOCK,
				    sizeof(sb->magic)))
				found_sb = true;
			else
				brelse(bh);
		}
	}
	/* Reverse previous increment */
	sec--;
	if (!found_sb) {
		lean_msg(s, KERN_ERR, "can't find a lean fs");
		goto failure;
	}

	lean_msg(s, KERN_INFO, "found superblock at sector %d", sec);

	s->s_magic = le32_to_cpup((__le32 *)sb->magic);
	if (sb->fs_version_major != LEAN_VERSION_MAJOR ||
	    sb->fs_version_minor != LEAN_VERSION_MINOR) {
		lean_msg(s, KERN_ERR, "unsupported version %u.%u",
			 sb->fs_version_major, sb->fs_version_minor);
		goto bh_failure;
	}
	if (lean_superblock_to_info(sb, sbi)) {
		lean_msg(s, KERN_ERR, "wrong superblock checksum");
		goto bh_failure;
	}
	if (!(sbi->state & LEAN_STATE_CLEAN))
		lean_msg(s, KERN_WARNING, "filesystem not unmounted properly");
	if (sbi->state & LEAN_STATE_ERROR)
		lean_msg(s, KERN_WARNING, "filesystem has major errors");
	if (sbi->super_primary != sec) {
		lean_msg(s, KERN_ERR, "inconsistent superblock");
		goto bh_failure;
	}
	if (!(s->s_flags & MS_RDONLY)) {
		sbi->sbh_backup = sb_bread(s, sbi->super_backup);
		if (!sbi->sbh_backup) {
			lean_msg(s, KERN_WARNING,
				 "cannot read backup superblock, remounting read-only");
			s->s_flags |= MS_RDONLY;
		}
	}
	/* The lower limit is spec specified (must use at least one sector for
	 * each bitmap chunk). The upper limit is not, however, but we impose
	 * it so we can store the number of free sectors as an unsigned 32-bit
	 * integer
	 */
	if (sbi->log2_band_sectors < 12 || sbi->log2_band_sectors > 32) {
		lean_msg(s, KERN_ERR,
			 "invalid number of sectors per band: %llu",
			 sbi->band_sectors);
		goto backup_failure;
	}
	/* Truncate the size of the disk to a multiple of 8 sectors
	 * It's not worth futzing around with sub-byte
	 * bitmap resolution for an extra few KiB
	 *
	 * This will silently shorten the disk
	 */
	diff = sbi->sectors_total & (8 - 1);
	if (diff) {
		sbi->sectors_total &= ~(8 - 1);
		sbi->sectors_free -= diff;
		sbi->band_count = (sbi->sectors_total + sbi->band_sectors - 1)
			/ sbi->band_sectors;
	}

	sbi->sbh = bh;
	s->s_fs_info = sbi;
	s->s_op = &lean_super_ops;
	mutex_init(&sbi->lock);

	ret = percpu_counter_init(&sbi->free_counter, sbi->sectors_free,
				  GFP_KERNEL);
	if (ret)
		goto backup_failure;

	ret = lean_bitmap_cache_init(s);
	if (ret)
		goto counter_failure;

	s->s_time_gran = 1000;
	s->s_maxbytes = MAX_LFS_FILESIZE;

	root = lean_iget(s, sbi->root);
	if (IS_ERR(root)) {
		ret = PTR_ERR(root);
		lean_msg(s, KERN_ERR, "error reading root inode:");
		goto bitmap_failure;
	}
	if (!S_ISDIR(root->i_mode) || !root->i_blocks || !root->i_size) {
		lean_msg(s, KERN_ERR, "corrupt root inode");
		iput(root);
		goto bitmap_failure;
	}

	s->s_root = d_make_root(root);
	if (!s->s_root) {
		lean_msg(s, KERN_ERR, "get root inode failed");
		ret = -ENOMEM;
		goto bitmap_failure;
	}

#ifndef LEAN_NO_OPTIONS
	save_mount_options(s, data);
#endif
	return lean_write_super(s);

bitmap_failure:
	lean_bitmap_cache_destroy(s);
counter_failure:
	percpu_counter_destroy(&sbi->free_counter);
backup_failure:
	if (!(s->s_flags & MS_RDONLY))
		brelse(sbi->sbh_backup);
bh_failure:
	brelse(bh);
failure:
	kfree(sbi);
	return ret;
#undef lean_msg
}

static struct dentry *lean_mount(struct file_system_type *fs_type, int flags,
				 const char *dev_name, void *data)
{
	return mount_bdev(fs_type, flags, dev_name, data, lean_fill_super);
}

static struct file_system_type lean_fs_type = {
	.owner = THIS_MODULE,
	.name = "lean",
	.mount = lean_mount,
	.kill_sb = kill_block_super,
	.fs_flags = FS_REQUIRES_DEV,
};

static int __init lean_init(void)
{
	int err = lean_init_inodecache();

	if (err)
		return err;

	err = register_filesystem(&lean_fs_type);
	if (err) {
		lean_destroy_inodecache();
		return err;
	}
	return 0;
}

static void __exit lean_exit(void)
{
	unregister_filesystem(&lean_fs_type);
	lean_destroy_inodecache();
}

module_init(lean_init);
module_exit(lean_exit);

MODULE_AUTHOR("Sean Anderson <seanga2@gmail.com>");
MODULE_DESCRIPTION("LEAN file system");
MODULE_LICENSE("GPL");
