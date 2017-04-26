#include "driver.h"
#include "lean.h"

#include <linux/buffer_head.h>
#include <linux/err.h>
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>

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
	.put_super = lean_put_super
};
	
static int lean_fill_super(struct super_block *s, void *data, int silent)
{
	bool found_sb = false;
	int ret = -EINVAL;
	int sec;
	struct buffer_head *bh;
	struct inode *root;
	struct lean_superblock *sb;
	struct lean_sb_info *sbi = kmalloc(sizeof(struct lean_sb_info), \
		GFP_KERNEL);

	if (!sbi) {
		return -ENOMEM;
	}

	if(!sb_set_blocksize(s, 512)) {
		pr_err("lean: cannot set block size of dev %s to 512\n",
			s->s_id);
		goto failure;
	}
	
	/* Try to read the superblock off sectors 1-32 */
	for (sec = 1; !found_sb && sec <= 32; sec++) {
		bh = sb_bread(s, sec);
		if (!bh) {
			pr_err("lean: Unable to read sector %d on dev %s\n", \
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
		pr_err("lean: Can't find a lean fs on dev %s\n", s->s_id);
		goto failure;
	}

	pr_debug("lean: found superblock at sector %d\n", sec);
	s->s_magic = le32_to_cpup((__le32 *) sb->magic);
	if (sb->fs_version_major != LEAN_VERSION_MAJOR || \
		sb->fs_version_minor != LEAN_VERSION_MINOR) {
		pr_err("lean: Unsupported version %u.%u\n", \
			sb->fs_version_major, sb->fs_version_minor);
		goto bh_failure;
	}
	if (le32_to_cpu(sb->state) != 1) {
		pr_err("lean: dev %s not unmounted properly\n", s->s_id);
		goto bh_failure;
	}
	if (lean_superblock_to_info(sb, sbi)) {
		pr_err("lean: Wrong superblock checksum\n");
		goto bh_failure;
	}
	if (sbi->super_primary != sec) {
		pr_err("lean: Inconsistant superblock\n");
		goto bh_failure;
	}
	if (sbi->log2_band_sectors < 12) {
		pr_err("lean: Invalid number of sectors per band: %llu\n", \
			sbi->band_sectors);
		goto bh_failure;
	}
	
	sbi->sbh = bh;
	s->s_fs_info = sbi;
	s->s_op = &lean_super_ops;
	
	memcpy(s->s_uuid, sbi->uuid, sizeof(s->s_uuid));
	strncpy(s->s_id, sbi->volume_label, sizeof(s->s_id));
	s->s_id[31] = '\0';

	s->s_flags |= MS_RDONLY;
	s->s_time_gran = 1000;
	
	root = lean_iget(s, sbi->root);
	if(IS_ERR(root)) {
		ret = PTR_ERR(root);
		goto bh_failure;
	}
	if(!S_ISDIR(root->i_mode) || !root->i_blocks || !root->i_size) {
		pr_err("lean: corrupt root inode\n");
		iput(root);
		goto bh_failure;
	}

	s->s_root = d_make_root(root);
	if(!s->s_root) {
		pr_err("lean: get root inode failed\n");
		ret = -ENOMEM;
		goto bh_failure;
	}

	return 0;
		
bh_failure:
	brelse(bh);
failure:
	kfree(sbi);
	return ret;
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
