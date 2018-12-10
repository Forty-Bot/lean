#include "lean.h"

/* We compile this file for both kernel and userspace use,
 * so we define some macros which later evaluate to the appropriate function
 */
#ifdef __KERNEL__
#include <linux/bug.h>
#include <linux/kernel.h>
#define tole16 cpu_to_le16
#define tole32 cpu_to_le32
#define tole64 cpu_to_le64
#define tocpu16 le16_to_cpu
#define tocpu32 le32_to_cpu
#define tocpu64 le64_to_cpu
#else // __KERNEL__
#include <endian.h>
#include <string.h>
#define tole16 htole16
#define tole32 htole32
#define tole64 htole64
#define tocpu16 le16toh
#define tocpu32 le32toh
#define tocpu64 le64toh
#endif // __KERNEL__

/*
 * Checksum function; does not include the first 4 bytes of the structure
 */
uint32_t lean_checksum(const void *data, size_t size)
{
	size_t i;
	uint32_t res = 0;
	const uint32_t *d = (const uint32_t *)data;

	lean_assert((size & (sizeof(uint32_t) - 1)) == 0);

	size /= sizeof(uint32_t);
	for (i = 1; i != size; i++)
		res = (res << 31) + (res >> 1) + d[i];
	return res;
}

/*
 * Extract superblock info from a superblock in disk format
 */
enum lean_error lean_superblock_to_info(const struct lean_superblock *sb,
			    struct lean_sb_info *sbi)
{
	int ret = 0;
	uint32_t cs;

	/* Error if the checksum is wrong, but still copy the data
	 * Useful for (for example) an fsck program
	 */
	cs = lean_checksum(sb, sizeof(*sb));
	if (cs != tocpu32(sb->checksum))
		ret = -LEAN_WRONG_CHECKSUM;

	sbi->prealloc = sb->prealloc + 1;
	sbi->log2_band_sectors = sb->log2_band_sectors;
	sbi->state = tocpu32(sb->state);
	memcpy(sbi->uuid, sb->uuid, sizeof(sbi->uuid));
	memcpy(sbi->volume_label, sb->volume_label, sizeof(sbi->volume_label));
	sbi->sectors_total = tocpu64(sb->sectors_total);
	sbi->sectors_free = tocpu64(sb->sectors_free);
	sbi->super_primary = tocpu64(sb->super_primary);
	sbi->super_backup = tocpu64(sb->super_backup);
	sbi->bitmap_start = tocpu64(sb->bitmap_start);
	sbi->root = tocpu64(sb->root);
	sbi->bad = tocpu64(sb->bad);

	sbi->band_sectors = 1 << sbi->log2_band_sectors;
	sbi->bitmap_size = 1 << (sbi->log2_band_sectors - 12);
	sbi->band_count = (sbi->sectors_total + sbi->band_sectors - 1)
		/ sbi->band_sectors;

	return ret;
}

/*
 * Convert superblock info to a disk format superblock
 * sb->reserved MUST be pre-initialized for a correct checksum
 * Always succeeds
 */
void lean_info_to_superblock(const struct lean_sb_info *sbi,
			     struct lean_superblock *sb)
{
	memcpy(sb->magic, LEAN_MAGIC_SUPERBLOCK, sizeof(sb->magic));
	sb->fs_version_major = LEAN_VERSION_MAJOR;
	sb->fs_version_minor = LEAN_VERSION_MINOR;
	sb->prealloc = sbi->prealloc - 1;
	sb->log2_band_sectors = sbi->log2_band_sectors;
	sb->state = tole32(sbi->state);
	memcpy(sb->uuid, sbi->uuid, sizeof(sb->uuid));
	memcpy(sb->volume_label, sbi->volume_label, sizeof(sb->volume_label));
	sb->sectors_total = tole64(sbi->sectors_total);
	sb->sectors_free = tole64(sbi->sectors_free);
	sb->super_primary = tole64(sbi->super_primary);
	sb->super_backup = tole64(sbi->super_backup);
	sb->bitmap_start = tole64(sbi->bitmap_start);
	sb->root = tole64(sbi->root);
	sb->bad = tole64(sbi->bad);
	sb->checksum = tole32(lean_checksum(sb, sizeof(*sb)));
}

/*
 * Extract inode data from a disk structure
 */
enum lean_error lean_inode_to_info(const struct lean_inode *raw,
				   struct lean_ino_info *li)
{
	int ret = 0;
	int i;
	uint32_t cs;

	cs = lean_checksum(raw, sizeof(*raw));
	if (cs != tocpu32(raw->checksum))
		ret = -LEAN_WRONG_CHECKSUM;

	li->extent_count = raw->extent_count;
	if (li->extent_count > LEAN_INODE_EXTENTS)
		li->extent_count = LEAN_INODE_EXTENTS;
	li->indirect_count = tocpu32(raw->indirect_count);
#ifndef __KERNEL__
	li->link_count = tocpu32(raw->link_count);
	li->uid = tocpu32(raw->uid);
	li->gid = tocpu32(raw->gid);
	li->attr = tocpu32(raw->attr);
	li->size = tocpu64(raw->size);
	li->sector_count = tocpu64(raw->sector_count);
	li->time_access = tocpu64(raw->time_access);
	li->time_status = tocpu64(raw->time_status);
	li->time_modify = tocpu64(raw->time_modify);
#endif
	li->time_create = tocpu64(raw->time_create);
	li->indirect_first = tocpu64(raw->indirect_first);
	li->indirect_last = tocpu64(raw->indirect_last);
	li->fork = tocpu64(raw->fork);
	for (i = 0; i < LEAN_INODE_EXTENTS; i++) {
		li->extent_starts[i] = tocpu64(raw->extent_starts[i]);
		li->extent_sizes[i] = tocpu32(raw->extent_sizes[i]);
	}
	return ret;
}

/*
 * Convert inode info to disk format
 * Any reserved data *must* be pre-initialized
 * lean_extra_to_inode should be called beforehand, if applicable
 */
void lean_info_to_inode(const struct lean_ino_info *li, struct lean_inode *raw)
{
	int i;

	memcpy(raw->magic, LEAN_MAGIC_INODE, sizeof(raw->magic));
	raw->extent_count = li->extent_count;
	if (li->extra)
		raw->extra_type = li->extra->type;
	else
		raw->extra_type = LXT_NONE;
	if (raw->extra_type == LXT_EXTENT
	    && raw->extent_count > LEAN_INODE_EXTENTS_MAX)
			raw->extent_count = LEAN_INODE_EXTENTS_MAX;
	else if (raw->extent_count > LEAN_INODE_EXTENTS)
		raw->extent_count = LEAN_INODE_EXTENTS;
	raw->indirect_count = tole32(li->indirect_count);
#ifndef __KERNEL__
	raw->link_count = tole32(li->link_count);
	raw->uid = tole32(li->uid);
	raw->gid = tole32(li->gid);
	raw->attr = tole32(li->attr);
	raw->size = tole64(li->size);
	raw->sector_count = tole64(li->sector_count);
	raw->time_access = tole64(li->time_access);
	raw->time_status = tole64(li->time_status);
	raw->time_modify = tole64(li->time_modify);
#endif
	raw->time_create = tole64(li->time_create);
	raw->indirect_first = tole64(li->indirect_first);
	raw->indirect_last = tole64(li->indirect_last);
	raw->fork = tole64(li->fork);
	for (i = 0; i < LEAN_INODE_EXTENTS; i++) {
		raw->extent_starts[i] = tole64(li->extent_starts[i]);
		raw->extent_sizes[i] = tole32(li->extent_sizes[i]);
	}
	raw->checksum = tole32(lean_checksum(raw, sizeof(*raw)));
}

enum lean_error lean_inode_to_extra(const struct lean_inode *raw,
			struct lean_extra_info *ex)
{
	unsigned i;

	ex->type = raw->extra_type;
	switch(ex->type) {
	case LXT_EXTENT:
		for (i = 0; i < LEAN_INODE_EXTRA_EXTENTS; i++) {
			ex->extent.starts[i]
				= tocpu64(raw->extra.extent.starts[i]);
			ex->extent.sizes[i]
				= tocpu32(raw->extra.extent.sizes[i]);
		}
		break;
	case LXT_DATA:
		memcpy(ex->data, raw->extra.data, LEAN_INODE_EXTRA);
		break;
	case LXT_XATTR:
		memcpy(ex->xattr, raw->extra.xattr, LEAN_INODE_EXTRA);
		break;
	case LXT_NONE:
		break;
	default:
		return -LEAN_INVALID_TYPE;
	}
	return 0;
}

void lean_extra_to_inode(const struct lean_extra_info *ex,
			 struct lean_inode *raw)
{
	unsigned i;

	raw->extra_type = ex->type;
	switch(ex->type) {
	case LXT_EXTENT:
		for (i = 0; i < LEAN_INODE_EXTRA_EXTENTS; i++) {
			raw->extra.extent.starts[i] =
				tocpu64(ex->extent.starts[i]);
			raw->extra.extent.sizes[i] =
				tocpu32(ex->extent.sizes[i]);
		}
		break;
	case LXT_DATA:
		memcpy(raw->extra.data, ex->data, LEAN_INODE_EXTRA);
		break;
	case LXT_XATTR:
		memcpy(raw->extra.xattr, ex->xattr, LEAN_INODE_EXTRA);
		break;
	case LXT_NONE:
	default:
		break;
	}
}

/*
 * Find the nth sector in an inode
 * count should contain the number of sectors we'd like to get
 * on successful return it contains the amount of following sectors up to the
 * input value of count
 * Must be called with li->lock held
 */
uint64_t lean_find_sector(struct lean_ino_info *li, uint64_t sec,
			  uint32_t *count)
{
	unsigned i = 0;
	uint64_t extent = li->extent_starts[i];
	uint32_t size = li->extent_sizes[i];

	/* Loop until we get to the right extent (or run out) */
	while (sec > size && i < li->extent_count) {
		extent = li->extent_starts[i];
		size = li->extent_sizes[i];
		sec -= size;
		i++;
	}

	if (sec <= size) {
		/* Try to map as many sectors as we can */
		for (i = 1; i < *count && sec + i < size; i++)
			;
		*count = i;
	} else {
		return 0;
	}
	return extent + sec;
}
