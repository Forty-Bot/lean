#include "driver.h"
#include "lean.h"

#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/pagemap.h>

/* Heavily influenced by fs/ext2/dir.c */
static unsigned int lean_last_byte(struct inode *inode, unsigned long page_nr)
{
	unsigned int last_byte = inode->i_size + sizeof(struct lean_inode);

	last_byte -= page_nr << PAGE_SHIFT;
	if (last_byte > PAGE_SIZE)
		last_byte = PAGE_SIZE;
	return last_byte;
}

static struct page *lean_get_page(struct inode *dir, unsigned long n)
{
	struct address_space *mapping = dir->i_mapping;
	struct page *page = read_mapping_page(mapping, n, NULL);

	if (!IS_ERR(page))
		kmap(page);
	return page;
}

static void lean_put_page(struct page *page)
{
		kunmap(page);
		put_page(page);
}

/* TODO: Remount as read-only on corrupt directory entry */
static int lean_readdir(struct inode *inode, struct dir_context *ctx,
			bool skip_empty)
{
	int ret = 0;
	struct super_block *s = inode->i_sb;
	/* This PAGE_SIZE will be subtracted off in the first loop iteration */
	unsigned int off = ctx->pos + PAGE_SIZE;
	unsigned long n = ctx->pos >> PAGE_SHIFT;
	unsigned long npages = dir_pages(inode);
	/* Skip the inode if the initial position is zero */
	if (!ctx->pos)
		off += sizeof(struct lean_inode);

	for (; n < npages; n++) {
		unsigned char *kaddr;
		struct lean_dir_entry *de;
		struct page *page = lean_get_page(inode, n);
		uint16_t length;

		off -= PAGE_SIZE;

		if (IS_ERR(page)) {
			lean_msg(s, KERN_ERR, "bad page in inode %lu",
				 inode->i_ino);
			ctx->pos += PAGE_SIZE - off;
			return PTR_ERR(page);
		}

		kaddr = page_address(page);
		de = (struct lean_dir_entry *)(kaddr + off);
		while (off <= lean_last_byte(inode, n)
			- sizeof(struct lean_dir_entry)) {
			/* Sanity checks */
			if (unlikely(!de->entry_length)) {
				lean_msg(s, KERN_ERR,
					 "zero-length directory entry in inode %lu",
					 inode->i_ino);
				lean_put_page(page);
				return -EIO;
			}
			/* Deleted entry */
			if (de->type == LFT_NONE && skip_empty)
				goto next;

			length = le16_to_cpu(de->name_length);
			if (skip_empty && unlikely(!length)) {
				lean_msg(s, KERN_ERR,
					 "zero-length directory name in inode %lu",
					 inode->i_ino);
				lean_put_page(page);
				return -EIO;
			} else if (skip_empty
				   && unlikely(length > de->entry_length
				   * sizeof(struct lean_dir_entry) - 12)) {
				lean_msg(s, KERN_ERR,
					 "directory name longer than directory entry in inode %lu",
					 inode->i_ino);
				lean_put_page(page);
				return -EIO;
			}

			if (unlikely(inode->i_size + sizeof(struct lean_inode)
				     < off
				     + de->entry_length * sizeof(struct lean_dir_entry)
				     + n * PAGE_SIZE)) {
				lean_msg(s, KERN_ERR,
					 "directory entry extends past directory size in inode %lu",
					 inode->i_ino);
				lean_put_page(page);
				return -EIO;
			}

			if (off	+ length >= PAGE_SIZE)
				/* Truncate the name to the page boundary */
				length = PAGE_SIZE - off;
			if (!dir_emit(ctx, de->name, length,
				      le64_to_cpu(de->inode),
				LEAN_DT(de->type))) {
				lean_put_page(page);
				return 0;
			}

next:
			off += de->entry_length * sizeof(struct lean_dir_entry);
			ctx->pos = off + n * PAGE_SIZE;
			de = (struct lean_dir_entry *)(kaddr + off);
		}
		lean_put_page(page);
	}
	return ret;
}

static int lean_iterate(struct file *file, struct dir_context *ctx)
{
	return lean_readdir(file_inode(file), ctx, true);
}

const struct file_operations lean_dir_ops = {
	.llseek = generic_file_llseek,
	.read = generic_read_dir,
	.iterate_shared = lean_iterate
};

struct lean_filename_match {
	struct dir_context ctx;
	ino_t ino;
	const unsigned char *name;
	int len;
};

static int lean_match(struct dir_context *ctx, const char *name, int len,
		      loff_t off, u64 ino, unsigned int type)
{
	struct lean_filename_match *match = (struct lean_filename_match *)ctx;

	if (len != match->len)
		return 0;

	if (memcmp(match->name, name, len) == 0) {
		match->ino = ino;
		return 1;
	}
	return 0;
}

static struct dentry *lean_lookup(struct inode *dir, struct dentry *de,
				  unsigned int flags)
{
	int err;
	ino_t ino;
	struct super_block *s = dir->i_sb;
	struct inode *inode = NULL;
	struct lean_filename_match match = {
		.ctx = { &lean_match, 0 },
		.name = de->d_name.name,
		.len = de->d_name.len
	};

	if (de->d_name.len > LEAN_DIR_NAME_MAX)
		return ERR_PTR(-ENAMETOOLONG);

	err = lean_readdir(dir, &match.ctx, true);
	if (err)
		return ERR_PTR(err);
	ino = match.ino;

	if (ino) {
		inode = lean_iget(s, ino);
		if (IS_ERR(inode)) {
			lean_msg(s, KERN_ERR, "cannot read inode %lu", ino);
			return ERR_PTR(PTR_ERR(inode));
		}
	}
	return d_splice_alias(inode, de);
}

const struct inode_operations lean_dir_inode_ops = {
	.lookup = lean_lookup,
	.setattr = lean_setattr
};
