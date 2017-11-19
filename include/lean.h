#ifndef LEANFS_H
#define LEANFS_H

/* Initialize some equivalent types so we can use this include in both user and
 * kernel space
 */
#ifdef __KERNEL__
#include <linux/types.h>
#include <linux/fs.h>
#define le16 __le16
#define le32 __le32
#define le64 __le64
struct lean_bitmap;
#else /* __KERNEL__ */
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#define le16 uint16_t
#define le32 uint32_t
#define le64 uint64_t
#define __packed __attribute__((__packed__))
#endif /* __KERNEL__ */

#define LEAN_TESTING

#define LEAN_VERSION_MAJOR 0x00
#define LEAN_VERSION_MINOR 0x06

static const uint8_t LEAN_MAGIC_SUPERBLOCK[] = { 'L', 'E', 'A', 'N' };
static const uint8_t LEAN_MAGIC_INDIRECT[] = { 'I', 'N', 'D', 'X' };
static const uint8_t LEAN_MAGIC_INODE[] = { 'N', 'O', 'D', 'E' };

#define LEAN_SEC 512
#define LEAN_SEC_MASK (LEAN_SEC - 1)
#define LEAN_SEC_SHIFT 9

/*
 * Structure containing fundamental information about a LEAN volume.
 */
struct lean_superblock {
	le32 checksum;
	uint8_t magic[4]; /* Must be LEAN_MAGIC_SUPERBLOCK */
	uint8_t fs_version_major; /* Should be LEAN_VERSION */
	uint8_t fs_version_minor;
	uint8_t prealloc; /* Extra sectors to allocate minus one */
	uint8_t log2_band_sectors; /* Number of sectors stored in each band */
	le32 state; /* Bit 0 is clean unmount. Bit 1 is error */
	uint8_t uuid[16];
	uint8_t volume_label[64]; /* UTF-8 name of volume */
	le64 sectors_total;
	le64 sectors_free;
	le64 super_primary;
	le64 super_backup;
	le64 bitmap_start; /* Sector of the first band's bitmap */
	le64 root; /* Inode of the root dir */
	le64 bad; /* Inode of a file consisting of bad sectors */
	uint8_t reserved[360];
} __packed;

#define LEAN_STATE_CLEAN 1
#define LEAN_STATE_ERROR 2

/*
 * Superblock info in memory
 */
struct lean_sb_info {
	uint8_t uuid[16];
	uint8_t volume_label[64];
	uint64_t sectors_total;
	uint64_t sectors_free;
	uint64_t super_primary;
	uint64_t super_backup;
	uint64_t bitmap_start; /* Sector of the first band's bitmap */
	uint64_t root; /* Inode of the root dir */
	uint64_t bad; /* Inode of a file consisting of bad sectors */
	/* End of on-disk members */
	uint64_t band_sectors; /* Number of sectors contained in one band */
	uint64_t band_count; /* Number of bands */
	uint64_t bitmap_size; /* Band bitmap size in sectors */
#ifdef __KERNEL__
	/*
	 * Protects writes to all members except the various bitmap
	 * fields, which are protected by the appropriate bitmap_cache lock
	 */
	struct mutex lock;
	struct percpu_counter free_counter;
	struct inode *bitmap;
	struct lean_bitmap *bitmap_cache;
	struct buffer_head *sbh;
	struct buffer_head *sbh_backup;
#else
	uint8_t *disk;
	int fd;
#endif
	/* Remaining on-disk members */
	uint32_t state;
	uint8_t prealloc; /* Extra sectors to allocate */
	uint8_t log2_band_sectors;
};

/*
 * Number of extents in an indirect
 */
#define LEAN_INDIRECT_EXTENTS 38

/*
 * Structure containing additional extents of a file
 */
struct lean_indirect {
	le32 checksum;
	uint8_t magic[4]; /* Must be LEAN_MAGIC_INDIRECT */
	le64 sector_count; /* Total amount of sectors in this index */
	le64 inode; /* Inode this indirect belongs to */
	le64 sector; /* The sector this indirect is in */
	le64 prev;
	le64 next;
	uint8_t extent_count; /* Total extents in this indirect */
	uint8_t reserved[7];
	/* Extents are split into two arrays for alignment */
	le64 extent_starts[LEAN_INDIRECT_EXTENTS];
	le32 extent_sizes[LEAN_INDIRECT_EXTENTS];
} __packed;

/*
 * Number of extents in an inode
 */
#define LEAN_INODE_EXTENTS 6

/*
 * Structure containing fundamental metadata of a file.
 * Resides in the first sector of the file, immediately before the data.
 */
struct lean_inode {
	le32 checksum;
	uint8_t magic[4]; /* Must be LEAN_MAGIC_INODE */
	uint8_t extent_count; /* Number of extents in this inode */
	uint8_t reserved[3];
	le32 indirect_count; /* Number of owned indirects */
	le32 link_count; /* Number of references to this file */
	le32 uid; /* User id of the owner */
	le32 gid; /* Group id of the owner */
	le32 attr; /* Attributes mask of the file; see: enum inode_attr */
	le64 size; /* Size of the data in bytes, not including metadata */
	le64 sector_count; /* Number of data sectors allocated */
	le64 time_access; /* Unix time of last access */
	le64 time_status; /* Unix time of last status change */
	le64 time_modify; /* Unix time of last modification */
	le64 time_create; /* Unix time of creation */
	le64 indirect_first;
	le64 indirect_last;
	le64 fork; /* Inode of fork, if existing */
	le64 extent_starts[LEAN_INODE_EXTENTS];
	le32 extent_sizes[LEAN_INODE_EXTENTS];
} __packed;

/*
 * Inode info in memory
 */
struct lean_ino_info {
#ifdef __KERNEL__
	/*
	 * Protects block allocation data (extent_*, indirect_*, sector_count)
	 * rwsem instead of mutex, as we expect more file accesses than writes
	 * TODO: profile and verify this
	 */
	struct rw_semaphore alloc_lock;
	struct inode vfs_inode;
#endif
	int64_t time_create; /* Unix time of creation */
	uint64_t indirect_first;
	uint64_t indirect_last;
	uint64_t fork; /* Inode of fork, if existing */
#ifndef __KERNEL__
	uint64_t size; /* Size of the data in bytes, not including metadata */
	uint64_t sector_count; /* Number of data sectors allocated */
	int64_t time_access; /* Unix time of last access */
	int64_t time_status; /* Unix time of last status change */
	int64_t time_modify; /* Unix time of last modification */
	uint32_t attr; /* Attributes mask of the file; see: enum inode_attr */
	uint32_t link_count; /* Number of references to this file */
	uid_t uid; /* User id of the owner */
	gid_t gid; /* Group id of the owner */
#endif
	uint32_t indirect_count; /* Number of owned indirects */
	uint8_t extent_count; /* Number of extents in this inode */
	uint64_t extent_starts[LEAN_INODE_EXTENTS];
	uint32_t extent_sizes[LEAN_INODE_EXTENTS];
};

/*
 * File type used in dir_entry
 * Analogous to IA_FMT
 */
enum lean_file_type {
	LFT_NONE = 0, /* An empty entry */
	LFT_REG = 1,
	LFT_DIR = 2,
	LFT_SYM = 3
};

#define LIA_FMT_SHIFT 29

/*
 * Enum containing all attributes of an inode
 * The bits are allocated as such:
 * 0xTTTXXXXXXXXXFFFFFFFFPPPPPPPPPPPP
 * Where P == Posix permissions
 *       F == Filesystem-specific attributes
 *       T == Filetype attributes
 *   and X == Unused
 */
enum lean_inode_attr {
	/* Posix permissions */
	LIA_RUSR = 1 << 8,
	LIA_WUSR = 1 << 7,
	LIA_XUSR = 1 << 6,
	LIA_RGRP = 1 << 5,
	LIA_WGRP = 1 << 4,
	LIA_XGRP = 1 << 3,
	LIA_ROTH = 1 << 2,
	LIA_WOTH = 1 << 1,
	LIA_XOTH = 1 << 0,
	LIA_SUID = 1 << 11, /* Execute as user id */
	LIA_SGID = 1 << 10, /* Execute as group id */
	LIA_SVTX = 1 << 9, /* Restrict rename/delete to owner */
	LIA_POSIX_MASK = (1 << 12) - 1, /* Mask of posix attributes */
	/* Filesystem-specific attributes */
	LIA_HIDDEN = 1 << 12, /* Do not show in default directory listings */
	LIA_SYSTEM = 1 << 13, /* Warn that this is a system file */
	LIA_ARCHIVE = 1 << 14, /* File changed since last backup */
	LIA_SYNC = 1 << 15, /* Writes must be committed immediately */
	LIA_NOATIME = 1 << 16, /* Do not update access time */
	LIA_IMMUTABLE = 1 << 17, /* Do not move file sectors */
	LIA_PREALLOC = 1 << 18, /* Keep preallocated sectors beyond inode.size
				 * after file is closed
				 */
	LIA_INLINE = 1 << 19, /* Inline extended attributes in first sector */
	/* Filetype attributes */
	LIA_FMT_REG = LFT_REG << LIA_FMT_SHIFT, /* Regular file */
	LIA_FMT_DIR = LFT_DIR << LIA_FMT_SHIFT, /* Directory */
	LIA_FMT_SYM = LFT_SYM << LIA_FMT_SHIFT, /* Symbolic link */
	LIA_FMT_FORK = (int)(4u << LIA_FMT_SHIFT), /* Fork */
	LIA_FMT_MASK = (int)(LIA_FMT_REG | LIA_FMT_DIR |
			     LIA_FMT_SYM | LIA_FMT_FORK),
};

#define LIA_ISFMT_REG(a) (((a) & LIA_FMT_REG) == LIA_FMT_REG)
#define LIA_ISFMT_DIR(a) (((a) & LIA_FMT_DIR) == LIA_FMT_DIR)
#define LIA_ISFMT_SYM(a) (((a) & LIA_FMT_SYM) == LIA_FMT_SYM)

/*
 * A 16-byte entry for a file in a directory
 * dir_entry.name may be longer or shorter than 4 bytes
 * However, the structure must be aligned to 16 bytes
 */
struct lean_dir_entry {
	le64 inode;
	uint8_t type; /* Type of the file, see: enum file_type */
	uint8_t entry_length; /* Length of the entry in 16-byte chunks */
	le16 name_length; /* Length of the name; may be other than 4 */
	uint8_t name[4]; /* May be larger or smaller than 4 */
} __packed;

#if 1
#define LEAN_DIR_NAME_MAX 255
#else
#define LEAN_DIR_NAME_MAX (256 * 16 - 12)
#endif

#define LEAN_DIR_ROUND (sizeof(struct lean_dir_entry) - 1)
#define LEAN_DIR_ENTRY_LEN(name_len) ((((name_len) \
					+ offsetof(struct lean_dir_entry, name) \
					+ LEAN_DIR_ROUND) & ~LEAN_DIR_ROUND) / \
				      sizeof(struct lean_dir_entry))

#define LEAN_DOTFILES_SIZE ((uint32_t)2 * sizeof(struct lean_dir_entry))

/* Time helper functions */
static inline uint64_t lean_time(struct timespec ts)
{
	return (ts.tv_sec * 1000000) + (ts.tv_nsec / 1000);
}

static inline struct timespec lean_timespec(int64_t time)
{
	struct timespec ts;

	ts.tv_sec = time / 1000000;
	ts.tv_nsec = (time % 1000000) * 1000;
	return ts;
}

/* util.c */
#define WRONG_CHECKSUM 1
uint32_t lean_checksum(const void *data, size_t size);
int lean_superblock_to_info(const struct lean_superblock *sb,
			    struct lean_sb_info *sbi);
void lean_info_to_superblock(const struct lean_sb_info *sbi,
			     struct lean_superblock *sb);
int lean_inode_to_info(const struct lean_inode *li, struct lean_ino_info *ii);
void lean_info_to_inode(const struct lean_ino_info *ii, struct lean_inode *li);

#endif // LEANFS_H
