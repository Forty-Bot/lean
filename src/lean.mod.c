#include <linux/module.h>
#include <linux/vermagic.h>
#include <linux/compiler.h>

MODULE_INFO(vermagic, VERMAGIC_STRING);

__visible struct module __this_module
__attribute__((section(".gnu.linkonce.this_module"))) = {
	.name = KBUILD_MODNAME,
	.init = init_module,
#ifdef CONFIG_MODULE_UNLOAD
	.exit = cleanup_module,
#endif
	.arch = MODULE_ARCH_INIT,
};

static const struct modversion_info ____versions[]
__used
__attribute__((section("__versions"))) = {
	{ 0x63dc1bdf, __VMLINUX_SYMBOL_STR(module_layout) },
	{ 0x1f5c4e1e, __VMLINUX_SYMBOL_STR(kmem_cache_destroy) },
	{ 0x548b9f0b, __VMLINUX_SYMBOL_STR(iget_failed) },
	{ 0x93966a6d, __VMLINUX_SYMBOL_STR(kmalloc_caches) },
	{ 0x3fe2ccbe, __VMLINUX_SYMBOL_STR(memweight) },
	{ 0xd2b09ce5, __VMLINUX_SYMBOL_STR(__kmalloc) },
	{ 0x3bb2ab1b, __VMLINUX_SYMBOL_STR(save_mount_options) },
	{ 0x762d6882, __VMLINUX_SYMBOL_STR(generic_file_llseek) },
	{ 0xdae80100, __VMLINUX_SYMBOL_STR(_raw_spin_unlock) },
	{ 0x37e62a12, __VMLINUX_SYMBOL_STR(__mark_inode_dirty) },
	{ 0xb8b6a76c, __VMLINUX_SYMBOL_STR(__percpu_counter_add) },
	{ 0x66d804b1, __VMLINUX_SYMBOL_STR(percpu_counter_destroy) },
	{ 0x60a13e90, __VMLINUX_SYMBOL_STR(rcu_barrier) },
	{ 0x4e8385f5, __VMLINUX_SYMBOL_STR(__lock_page) },
	{ 0x80c6ff38, __VMLINUX_SYMBOL_STR(put_zone_device_page) },
	{ 0xbf63e976, __VMLINUX_SYMBOL_STR(mutex_unlock) },
	{ 0x4d1ff991, __VMLINUX_SYMBOL_STR(mount_bdev) },
	{ 0x9c31400c, __VMLINUX_SYMBOL_STR(generic_read_dir) },
	{ 0x28aa6a67, __VMLINUX_SYMBOL_STR(call_rcu) },
	{ 0x42846bac, __VMLINUX_SYMBOL_STR(set_page_dirty) },
	{ 0xa26d7294, __VMLINUX_SYMBOL_STR(mpage_readpages) },
	{ 0xe0a51e1, __VMLINUX_SYMBOL_STR(mpage_readpage) },
	{ 0x269cfd2a, __VMLINUX_SYMBOL_STR(mutex_lock_interruptible) },
	{ 0xaa9791ca, __VMLINUX_SYMBOL_STR(__bread_gfp) },
	{ 0xf0c2bfce, __VMLINUX_SYMBOL_STR(__mutex_init) },
	{ 0x27e1a049, __VMLINUX_SYMBOL_STR(printk) },
	{ 0x449ad0a7, __VMLINUX_SYMBOL_STR(memcmp) },
	{ 0x4a2b2886, __VMLINUX_SYMBOL_STR(mpage_writepages) },
	{ 0x479c3c86, __VMLINUX_SYMBOL_STR(find_next_zero_bit) },
	{ 0x9166fada, __VMLINUX_SYMBOL_STR(strncpy) },
	{ 0xc634d149, __VMLINUX_SYMBOL_STR(kmem_cache_free) },
	{ 0x16305289, __VMLINUX_SYMBOL_STR(warn_slowpath_null) },
	{ 0x3182fee4, __VMLINUX_SYMBOL_STR(set_nlink) },
	{ 0x8e9fbcb7, __VMLINUX_SYMBOL_STR(setattr_copy) },
	{ 0x69d98018, __VMLINUX_SYMBOL_STR(sync_dirty_buffer) },
	{ 0x5240ee7, __VMLINUX_SYMBOL_STR(percpu_counter_batch) },
	{ 0xe4a03103, __VMLINUX_SYMBOL_STR(generic_file_read_iter) },
	{ 0xb4ad5836, __VMLINUX_SYMBOL_STR(__brelse) },
	{ 0xe2cc8183, __VMLINUX_SYMBOL_STR(inode_init_once) },
	{ 0x9d9a66e, __VMLINUX_SYMBOL_STR(kmem_cache_alloc) },
	{ 0xdb7305a1, __VMLINUX_SYMBOL_STR(__stack_chk_fail) },
	{ 0xb2f726df, __VMLINUX_SYMBOL_STR(mpage_writepage) },
	{ 0xfe84dd01, __VMLINUX_SYMBOL_STR(unlock_new_inode) },
	{ 0x5b83a33e, __VMLINUX_SYMBOL_STR(kill_block_super) },
	{ 0xb905c66, __VMLINUX_SYMBOL_STR(__percpu_counter_init) },
	{ 0xbdfb6dbb, __VMLINUX_SYMBOL_STR(__fentry__) },
	{ 0x3cf5e967, __VMLINUX_SYMBOL_STR(kmem_cache_alloc_trace) },
	{ 0xe259ae9e, __VMLINUX_SYMBOL_STR(_raw_spin_lock) },
	{ 0x2753893, __VMLINUX_SYMBOL_STR(generic_show_options) },
	{ 0xd18d4259, __VMLINUX_SYMBOL_STR(kmem_cache_create) },
	{ 0x6907cb63, __VMLINUX_SYMBOL_STR(register_filesystem) },
	{ 0xd8547967, __VMLINUX_SYMBOL_STR(iput) },
	{ 0xe9abce3f, __VMLINUX_SYMBOL_STR(read_cache_page) },
	{ 0x37a0cba, __VMLINUX_SYMBOL_STR(kfree) },
	{ 0x2ac52c51, __VMLINUX_SYMBOL_STR(d_splice_alias) },
	{ 0x422b842, __VMLINUX_SYMBOL_STR(sb_set_blocksize) },
	{ 0x875a84e9, __VMLINUX_SYMBOL_STR(d_make_root) },
	{ 0x93d3227e, __VMLINUX_SYMBOL_STR(mark_buffer_dirty) },
	{ 0x45010043, __VMLINUX_SYMBOL_STR(unregister_filesystem) },
	{ 0xe38955dc, __VMLINUX_SYMBOL_STR(write_one_page) },
	{ 0x9f5a47d3, __VMLINUX_SYMBOL_STR(new_inode) },
	{ 0x6298e3a, __VMLINUX_SYMBOL_STR(__put_page) },
	{ 0x75768d0e, __VMLINUX_SYMBOL_STR(iget_locked) },
	{ 0xf812cff6, __VMLINUX_SYMBOL_STR(memscan) },
	{ 0xefd2b43f, __VMLINUX_SYMBOL_STR(setattr_prepare) },
};

static const char __module_depends[]
__used
__attribute__((section(".modinfo"))) =
"depends=";

