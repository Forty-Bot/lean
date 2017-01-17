#include "lean.h"

#include <linux/module.h>
#include <linux/fs.h>
#include <linux/err.h>

static struct lean_superblock *lean_sb_read(struct super_block *sb)
{
	return NULL;
}

static int lean_fill_super(struct super_block *sb, void *data, int flags)
{
	return 0;
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
