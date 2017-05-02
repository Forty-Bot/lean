#include "driver.h"
#include "lean.h"

#include <linux/buffer_head.h>
#include <linux/err.h>
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/statfs.h>
#include <linux/slab.h>

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
	struct lean_sb_info *sbi = (struct lean_sb_info *) de->d_sb->s_fs_info;
	uint64_t fsid;

	strncpy((void *) &buf->f_type,
		LEAN_MAGIC_SUPERBLOCK, sizeof(buf->f_type));
	buf->f_bsize = buf->f_frsize = 512;
	buf->f_blocks = sbi->sectors_total;
	buf->f_bfree = buf->f_bavail = sbi->sectors_free;
	/* We don't have hard inode limits, so don't bother */
	buf->f_files = buf->f_ffree = 0;
	/* Ripped from fs/ext2/super.c */
	fsid = le64_to_cpup((void *) sbi->uuid) ^
	       le64_to_cpup((void *) sbi->uuid + sizeof(uint64_t));
	buf->f_fsid.val[0] = fsid & 0xFFFFFFFFUL;
	buf->f_fsid.val[1] = (fsid >> 32) & 0xFFFFFFFFUL;
	buf->f_namelen = LEAN_DIR_NAME_MAX;
	buf->f_flags = de->d_sb->s_flags;
	return 0;
}

static void lean_put_super(struct super_block *s)
{
	struct lean_sb_info *sbi = (struct lean_sb_info *) s->s_fs_info;
	
	/* TODO: Write sb to disk before destroying it */
	brelse(sbi->sbh);
	s->s_fs_info = NULL;
	kfree(sbi);
}

static struct kmem_cache *lean_inode_cache;

struct inode *lean_inode_alloc(struct super_block *s)
{
	struct lean_ino_info *inode;
	inode = kmem_cache_alloc(lean_inode_cache, GFP_KERNEL);
	if (!inode)
		return NULL;
	return &inode->vfs_inode;
}

static void lean_free_callback(struct rcu_head *head) {
	struct inode *inode = container_of(head, struct inode, i_rcu);
	kmem_cache_free(lean_inode_cache, LEAN_I(inode));
}

static void lean_inode_free(struct inode *inode)
{
	call_rcu(&inode->i_rcu, lean_free_callback);
}

static void lean_inode_init_once(void *i)
{
	struct lean_ino_info *inode = (struct lean_ino_info *) i;
	inode_init_once(&inode->vfs_inode);
}

static int __init lean_init_inodecache(void)
{
	lean_inode_cache = kmem_cache_create("lean_inode_cache",
			sizeof(struct lean_ino_info), 0,
			(SLAB_RECLAIM_ACCOUNT | SLAB_MEM_SPREAD | SLAB_ACCOUNT),
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
	.statfs = lean_statfs
};
	
static int lean_fill_super(struct super_block *s, void *data, int silent)
{
#define lean_msg(s, prefix, fmt, ...) \
if (!silent) { \
	lean_msg(s, prefix, fmt, ##__VA_ARGS__); \
}

	bool found_sb = false;
	int ret = -EINVAL;
	int sec;
	struct buffer_head *bh;
	struct inode *root;
	struct lean_superblock *sb;
	struct lean_sb_info *sbi = kmalloc(sizeof(struct lean_sb_info),
		GFP_KERNEL);

	if (!sbi) {
		return -ENOMEM;
	}

	if(!sb_set_blocksize(s, 512)) {
		lean_msg(s, KERN_ERR, "cannot set block size of dev %s to 512",
			s->s_id);
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
			sb = (struct lean_superblock *) bh->b_data;
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
		lean_msg(s, KERN_ERR, "can't find a lean fs on dev %s",
			s->s_id);
		goto failure;
	}

	lean_msg(s, KERN_INFO, "found superblock at sector %d", sec);
	s->s_magic = le32_to_cpup((__le32 *) sb->magic);
	if (sb->fs_version_major != LEAN_VERSION_MAJOR || \
		sb->fs_version_minor != LEAN_VERSION_MINOR) {
		lean_msg(s, KERN_ERR, "unsupported version %u.%u",
			sb->fs_version_major, sb->fs_version_minor);
		goto bh_failure;
	}
	if (le32_to_cpu(sb->state) != 1) {
		lean_msg(s, KERN_WARNING, "dev %s not unmounted properly!",
			s->s_id);
	}
	if (lean_superblock_to_info(sb, sbi)) {
		lean_msg(s, KERN_ERR, "wrong superblock checksum");
		goto bh_failure;
	}
	if (sbi->super_primary != sec) {
		lean_msg(s, KERN_ERR, "inconsistant superblock");
		goto bh_failure;
	}
	if (sbi->log2_band_sectors < 12) {
		lean_msg(s, KERN_ERR,
			"invalid number of sectors per band: %llu",
			sbi->band_sectors);
		goto bh_failure;
	}
	
	sbi->sbh = bh;
	s->s_fs_info = sbi;
	s->s_op = &lean_super_ops;
	
	memcpy(s->s_uuid, sbi->uuid, sizeof(s->s_uuid));
	strncpy(s->s_id, sbi->volume_label, sizeof(s->s_id));
	s->s_id[31] = '\0';

	/*s->s_flags |= MS_RDONLY;*/
	s->s_time_gran = 1000;
	
	root = lean_iget(s, sbi->root);
	if(IS_ERR(root)) {
		ret = PTR_ERR(root);
		lean_msg(s, KERN_ERR, "error reading root inode:");
		goto bh_failure;
	}
	if(!S_ISDIR(root->i_mode) || !root->i_blocks || !root->i_size) {
		lean_msg(s, KERN_ERR, "corrupt root inode");
		iput(root);
		goto bh_failure;
	}

	s->s_root = d_make_root(root);
	if(!s->s_root) {
		lean_msg(s, KERN_ERR, "get root inode failed");
		ret = -ENOMEM;
		goto bh_failure;
	}

	return 0;
		
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
	int err;
	err = lean_init_inodecache();
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
