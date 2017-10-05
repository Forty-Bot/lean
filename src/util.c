#include "lean.h"

/* We compile this file for both kernel and userspace use,
 * so we define some macros which later evaluate to the appropriate function
 */
#ifdef __KERNEL__
#include <linux/bug.h>
#include <linux/kernel.h>
#define lean_assert(x) WARN_ON_ONCE(!(x))
#define tole16 cpu_to_le16
#define tole32 cpu_to_le32
#define tole64 cpu_to_le64
#define tocpu16 le16_to_cpu
#define tocpu32 le32_to_cpu
#define tocpu64 le64_to_cpu
#else // __KERNEL__
#include <assert.h>
#include <endian.h>
#include <string.h>
#define lean_assert assert
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
int lean_superblock_to_info(const struct lean_superblock *sb,
			    struct lean_sb_info *sbi)
{
	int ret = 0;
	uint32_t cs;

	/* Error if the checksum is wrong, but still copy the data
	 * Useful for (for example) an fsck program
	 */
	cs = lean_checksum(sb, sizeof(*sb));
	if (cs != tocpu32(sb->checksum))
		ret = -WRONG_CHECKSUM;

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
int lean_inode_to_info(const struct lean_inode *li, struct lean_ino_info *ii)
{
	int ret = 0;
	int i;
	uint32_t cs;

	cs = lean_checksum(li, sizeof(*li));
	if (cs != tocpu32(li->checksum))
		ret = -WRONG_CHECKSUM;

	ii->extent_count = li->extent_count;
	if (ii->extent_count > LEAN_INODE_EXTENTS)
		ii->extent_count = LEAN_INODE_EXTENTS;
	ii->indirect_count = tocpu32(li->indirect_count);
#ifndef __KERNEL__
	ii->link_count = tocpu32(li->link_count);
	ii->uid = tocpu32(li->uid);
	ii->gid = tocpu32(li->gid);
	ii->attr = tocpu32(li->attr);
	ii->size = tocpu64(li->size);
	ii->sector_count = tocpu64(li->sector_count);
	ii->time_access = tocpu64(li->time_access);
	ii->time_status = tocpu64(li->time_status);
	ii->time_modify = tocpu64(li->time_modify);
#endif
	ii->time_create = tocpu64(li->time_create);
	ii->indirect_first = tocpu64(li->indirect_first);
	ii->indirect_last = tocpu64(li->indirect_last);
	ii->fork = tocpu64(li->fork);
	for (i = 0; i < LEAN_INODE_EXTENTS; i++) {
		ii->extent_starts[i] = tocpu64(li->extent_starts[i]);
		ii->extent_sizes[i] = tocpu32(li->extent_sizes[i]);
	}
	return ret;
}

/*
 * Convert inode info to disk format
 * Any reserved data *must* be pre-initialized
 */
void lean_info_to_inode(const struct lean_ino_info *ii, struct lean_inode *li)
{
	int i;

	memcpy(li->magic, LEAN_MAGIC_INODE, sizeof(li->magic));
	li->extent_count = ii->extent_count;
	if (li->extent_count > LEAN_INODE_EXTENTS)
		li->extent_count = LEAN_INODE_EXTENTS;
	li->indirect_count = tole32(ii->indirect_count);
#ifndef __KERNEL__
	li->link_count = tole32(ii->link_count);
	li->uid = tole32(ii->uid);
	li->gid = tole32(ii->gid);
	li->attr = tole32(ii->attr);
	li->size = tole64(ii->size);
	li->sector_count = tole64(ii->sector_count);
	li->time_access = tole64(ii->time_access);
	li->time_status = tole64(ii->time_status);
	li->time_modify = tole64(ii->time_modify);
#endif
	li->time_create = tole64(ii->time_create);
	li->indirect_first = tole64(ii->indirect_first);
	li->indirect_last = tole64(ii->indirect_last);
	li->fork = tole64(ii->fork);
	for (i = 0; i < LEAN_INODE_EXTENTS; i++) {
		li->extent_starts[i] = tole64(ii->extent_starts[i]);
		li->extent_sizes[i] = tole32(ii->extent_sizes[i]);
	}
	li->checksum = tole32(lean_checksum(li, sizeof(*li)));
}
