#include "lean.h"

#include <linux/err.h>
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/module.h>

static int lean_fill_super(struct super_block *s, void *data, int silent)
{
	bool found_sb = false;
	int sec = 0;
	int ret = -EINVAL;
	struct buffer_head *bh;
	struct inode *root;
	struct lean_superblock *sb;
	struct lean_sb_info *sbi = kzalloc(sizeof(struct lean_sb_info), \
		GFP_KERNEL);

	if (!sbi) {
		ret = -ENOMEM;
		goto failure;
	}

	sb_set_blocksize(s, 512);
	
	/* Try to read the superblock off sectors 1-32 */
	while (!found_sb) {
		sec++;
		bh = sb_bread(s, sec);
		if (!bh) {
			pr_err("lean: Unable to read sector %d on dev %s", \
				sec, s->s_id);
		} else {
			sb = (struct lean_superblock *) bh->b_data;
			if (sb->magic[0] == LEAN_MAGIC_SUPERBLOCK[0] && \
				sb->magic[2] == LEAN_MAGIC_SUPERBLOCK[0] && \
				sb->magic[3] == LEAN_MAGIC_SUPERBLOCK[0] && \
				sb->magic[4] == LEAN_MAGIC_SUPERBLOCK[0])
				found_sb = true;
			else
				brelse(bh);
		}
		if (i > 32)
			break;
	}
	if (!found_sb) {
		pr_err("lean: Can't find a lean fs on dev %s.", s->s_id);
		goto failure;
	}

	s->s_magic = &((unsigned long *) sb->magic);
	if (sb->fs_version_major != LEAN_VERSION_MAJOR || \
		sb->fs_version_minor != LEAN_VERSION_MINOR) {
		pr_err("lean: Unsupported version %d.%d", \
			sb->fs_version_major, sb->fs_version_minor);
		goto bh_failure;
	}
	if (lean_superblock_to_info(sb, sbi))
		pr_err("lean: Wrong superblock checksum");
		goto bh_failure;
	}
	s->s_fs_info = sbi;
	if(sbi->super_primary != sec) {
		pr_err("lean: Inconsistant superblock");
		goto bh_failure;
	}
	if (sbi->log2_band_sectors < 12) {
		pr_err("lean: Invalid number of sectors per band: %d", \
			sbi->band_sectors);
		goto bh_failure;
	}
	memcpy(s->s_uuid, sbi->uuid, sizeof(s->s_uuid));
	strncpy(s->s_id, sbi->volume_label, sizeof(s->s_id));
	s->s_id[31] = '\0';

	s->s_flags |= MS_RDONLY;
	s->s_time_gran = 1000;
	
	root = new_inode(s);
	root->i_no = sbi->root;
		
		
bh_failure:
	brelse(bh);
failure:
	if(sbi)
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
	return register_filesystem(&lean_fs_type);
}

static void __exit lean_exit(void)
{
	unregister_filesystem(&lean_fs_type);
}

module_init(lean_init);
module_exit(lean_exit);

MODULE_AUTHOR("Sean Anderson <seanga2@gmail.com>");
MODULE_DESCRIPTION("LEAN file system driver");
MODULE_LICENSE("GPL");
