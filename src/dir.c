#include "kernel.h"
#include "lean.h"

#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/pagemap.h>

/* Heavily influenced by fs/ext2/dir.c */
static unsigned int lean_last_byte(struct inode *inode, unsigned long page_nr)
{
	unsigned int last_byte = inode->i_size;

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

/*
 * Iterate over a directory, emiting dentries to the ctx
 * If emit_empty is true, empty entries are emitted as well and name_length
 * sanity checks are disabled
 * If lock is true, the page containing the dir_entry is locked before emitting
 * the entry. If ctx->actor returns 1, we assume it has unlocked the page
 * TODO: Remount as read-only on corrupt directory entry
 */
static int lean_readdir(struct inode *inode, struct dir_context *ctx,
			bool emit_empty, bool lock)
{
	int ret = 0;
	struct super_block *s = inode->i_sb;
	/* This PAGE_SIZE will be subtracted off in the first loop iteration */
	unsigned int off = ctx->pos + PAGE_SIZE;
	unsigned long n = ctx->pos >> PAGE_SHIFT;
	unsigned long npages = dir_pages(inode);

	for (; !ret && n < npages; n++) {
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

		if (lock)
			lock_page(page);
		kaddr = page_address(page);
		de = (struct lean_dir_entry *)(kaddr + off);
		while (off <= lean_last_byte(inode, n)
			- sizeof(struct lean_dir_entry)) {
			/* Sanity checks */
			if (unlikely(!de->entry_length)) {
				lean_msg(s, KERN_ERR,
					 "zero-length directory entry in inode %lu",
					 inode->i_ino);
				ret = -EIO;
				break;
			}
			/* Deleted entry */
			if (de->type == LFT_NONE && !emit_empty)
				goto next;

			length = le16_to_cpu(de->name_length);
			if (!emit_empty && unlikely(!length)) {
				lean_msg(s, KERN_ERR,
					 "zero-length directory name in inode %lu",
					 inode->i_ino);
				ret = -EIO;
				break;
			} else if (!emit_empty &&
				   unlikely(length > de->entry_length
				   * sizeof(struct lean_dir_entry) - 12)) {
				lean_msg(s, KERN_ERR,
					 "directory name longer than directory entry in inode %lu",
					 inode->i_ino);
				ret = -EIO;
				break;
			}

			if (unlikely(inode->i_size + sizeof(struct lean_inode)
				     < off
				     + de->entry_length * sizeof(struct lean_dir_entry)
				     + n * PAGE_SIZE)) {
				lean_msg(s, KERN_ERR,
					 "directory entry extends past directory size in inode %lu",
					 inode->i_ino);
				ret = -EIO;
				break;
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
		if (lock)
			unlock_page(page);
		lean_put_page(page);
	}
	return ret;
}

static int lean_iterate(struct file *file, struct dir_context *ctx)
{
	return lean_readdir(file_inode(file), ctx, false, false);
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

	err = lean_readdir(dir, &match.ctx, false, false);
	if (err)
		return ERR_PTR(err);
	ino = match.ino;

	if (ino) {
		inode = lean_iget(s, ino);
		if (IS_ERR(inode)) {
			lean_msg(s, KERN_ERR, "cannot read inode %lu", ino);
			return ERR_CAST(inode);
		}
	}
	return d_splice_alias(inode, de);
}

struct lean_add_link_data {
	struct dir_context ctx;
	uint64_t inode;
	const unsigned char *name;
	int err;
	uint8_t type;
	uint8_t entry_length;
	uint8_t name_length;
	uint8_t preceding;
};

static int lean_add_link_iter(struct dir_context *ctx, char *name,
			      int len, loff_t off, u64 ino, unsigned int type)
{
	loff_t length;
	struct page *page;
	struct inode *dir;
	struct lean_add_link_data *data = (struct lean_add_link_data *)ctx;
	/* Can't use container_of because we have an array literal */
	struct lean_dir_entry *start, *de =
		(struct lean_dir_entry *)
		(name - offsetof(struct lean_dir_entry, name));
	uint8_t size;

	/*
	 * If there's not enough space for our entry in this sector, or this
	 * entry isn't empty, skip this entry.
	 */
	if (de->type != LFT_NONE ||
	    data->entry_length * sizeof(struct lean_dir_entry) +
	    (off & LEAN_SEC_MASK) -
	    data->preceding * sizeof(struct lean_dir_entry) > LEAN_SEC) {
		data->preceding = 0;
		return 0;
	}
	start = de - data->preceding;
	size = de->entry_length + data->preceding;
	if (data->entry_length > size) {
		data->preceding = size;
		return 0;
	} else if (data->entry_length < size) {
	/*
	 * Set up the following empty dir entry; we only need to do this if we
	 * have extra space following our new entry.
	 */
		struct lean_dir_entry *end = start + data->entry_length;

		memset(end, 0, sizeof(*end));
		end->type = LFT_NONE;
		end->entry_length = size - data->entry_length;
	}

	memset(start, 0, sizeof(*start));
	start->inode = cpu_to_le64(data->inode);
	start->type = data->type;
	start->entry_length = data->entry_length;
	start->name_length = cpu_to_le16(data->name_length);
	memcpy(start->name, data->name, data->name_length);

	page = kmap_to_page(name);
	dir = page->mapping->host;
	length = off - (de->entry_length * sizeof(struct lean_dir_entry));
	/* Check to see if we went over the end of the directory */
	if (length > dir->i_size) {
		i_size_write(dir, length);
		mark_inode_dirty(dir);
	}

	dir->i_mtime = dir->i_ctime = current_time(dir);
	mark_inode_dirty(dir);

	set_page_dirty(page);
	data->err = 0;
	if (IS_DIRSYNC(dir)) {
		data->err = lean_write_page(page, 1);
		if (!data->err)
			data->err = sync_inode_metadata(dir, 1);
		else
			unlock_page(page);
	} else {
		unlock_page(page);
	}

	return 1;
}

static int lean_add_link(struct dentry *de, struct inode *inode)
{
	int err;
	struct inode *dir = d_inode(de->d_parent);
	struct lean_add_link_data data = {
		/* We need a cast here because kmap_to_page discards const */
		.ctx = { (filldir_t)lean_add_link_iter, 0 },
		.inode = inode->i_ino,
		.name = de->d_name.name,
		.type = LEAN_FT(inode->i_mode),
		.entry_length = LEAN_DIR_ENTRY_LEN(de->d_name.len),
		.name_length = de->d_name.len,
		/* 1 == not found, 0 == found, < 0 == found with errors */
		.err = 1,
	};

	err = lean_readdir(dir, &data.ctx, true, true);
	if (err)
		return err;

	if (data.err == 1) {
		struct page *page;
		struct lean_dir_entry *new;
		loff_t off = data.ctx.pos -
			     data.preceding * sizeof(struct lean_dir_entry);

		if ((off & LEAN_SEC_MASK) + data.entry_length > LEAN_SEC_MASK)
			off = (off + LEAN_SEC_MASK) & LEAN_SEC_MASK;

		if (!off) {
			WARN_ON(true);
			return -EINVAL;
		}

		page = lean_get_page(dir, off >> PAGE_SHIFT);
		if (IS_ERR(page))
			return PTR_ERR(page);
		lock_page(page);

		data.ctx.pos = off;
		data.preceding = 0;
		new = page_address(page) + (off & PAGE_MASK);
		new->type = LFT_NONE;
		new->entry_length = data.entry_length;

		/* XXX: returns 1 on success */
		err = lean_add_link_iter(&data.ctx, new->name, 0,
					 off, inode->i_ino, DT_UNKNOWN);
		if (!err || data.err) {
			lean_msg(inode->i_sb, KERN_DEBUG,
				 "failed to extend directory err = %d data.err = %d",
				 err, data.err);
			unlock_page(page);
			lean_put_page(page);
			if (!err)
				return -EINVAL;
		} else {
			lean_put_page(page);
		}
		lean_msg(inode->i_sb, KERN_DEBUG,
			 "created dir_entry... %16ph", new);
	}

	return data.err;
}

static int lean_create(struct inode *dir, struct dentry *dentry,
		       umode_t mode, bool excl)
{
	int err;
	struct inode *inode;

	lean_msg(dir->i_sb, KERN_DEBUG, "trying to allocate new inode...");
	inode = lean_new_inode(dir, mode);
	if (IS_ERR(inode))
		return PTR_ERR(inode);

	lean_msg(dir->i_sb, KERN_DEBUG, "got inode, linking to dir...");
	err = lean_add_link(dentry, inode);
	if (err) {
		inode_dec_link_count(inode);
		unlock_new_inode(inode);
		iput(inode);
		return err;
	}

	unlock_new_inode(inode);
	d_instantiate(dentry, inode);
	return 0;
}

const struct inode_operations lean_dir_inode_ops = {
	.create = lean_create,
	.lookup = lean_lookup,
	.setattr = lean_setattr,
};
