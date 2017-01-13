#ifndef LEANFS_H
#define LEANFS_H

#include <stdint.h>

#define LEAN_VERSION 0x0006 /* 0.6 */

#define MAGIC_SUPERBLOCK 0x4E41454C /* LEAN */
#define MAGIC_INDIRECT 0x58444E49 /* INDX */ 
#define MAGIC_INODE 0x45444F4E /* NODE */

/*
 * Structure containing fundamental information about a LEAN volume.
 */
struct superblock {
	uint32_t checksum;
	uint32_t magic; /* Must be MAGIC_SUPERBLOCK */
	uint16_t fs_version; /* Should be LEAN_VERSION; others unsupported */
	uint8_t prealloc_count; /* Extra sectors to allocate minus one */
	uint8_t log2_sectors_per_band;
	uint32_t state; /* Bit 0 is clean unmount. Bit 1 is error */
	uint8_t uuid[16];
	uint8_t volume_label[64]; /* UTF-8 name of volume */
	uint64_t sectors_total;
	uint64_t sectors_free;
	uint64_t super_primary;
	uint64_t super_backup;
	uint64_t bitmap_start; /* Sector of the first band's bitmap */
	uint64_t root; /* Inode of the root dir */
	uint64_t bad; /* Inode of a file consisting of bad sectors */
	uint8_t reserved[360];
} __attribute__((packed));

/* 
 * Number of extents in an indirect
 */
#define INDIRECT_EXTENTS 38

/*
 * Structure containing additional extents of a file
 */
struct indirect {
	uint32_t checksum;
	uint32_t magic; /* Must be MAGIC_INDIRECT */
	uint64_t sector_count; /* Total amount of sectors in this index */
	uint64_t inode; /* Inode this indirect belongs to */
	uint64_t sector; /* The sector this indirect is in */
	uint64_t prev; 
	uint64_t next;
	uint8_t extent_count; /* Total extents in this indirect */
	uint8_t reserved[7];
	/* Extents are split into two arrays for alignment */
	uint64_t extent_starts[INDIRECT_EXTENTS];
	uint32_t extent_sizes[INDIRECT_EXTENTS];
} __attribute__((packed));

/*
 * Number of extents in an inode
 */
#define INODE_EXTENTS 6

/*
 * Structure containing fundamental metadata of a file.
 * Resides in the first sector of the file, immediately before the data.
 */
struct inode {
	uint32_t checksum;
	uint32_t magic; /* Must be MAGIC_INODE */
	uint8_t extent_count; /* Number of extents in this inode */
	uint8_t reserved[3];
	uint32_t indirect_count; /* Number of owned indirects */
	uint32_t link_count; /* Number of references to this file */
	uint32_t uid; /* User id of the owner */
	uint32_t gid; /* Group id of the owner */
	uint32_t attr; /* Attributes mask of the file; see: enum inode_attr */
	uint64_t size; /* Size of the data in bytes, not including metadata */
	uint64_t sector_count; /* Number of data sectors allocated */
	int64_t time_access; /* Unix time of last access */
	int64_t time_status; /* Unix time of last status change */
	int64_t time_modify; /* Unix time of last modification */
	int64_t time_create; /* Unix time of creation */
	uint64_t indirect_first;
	uint64_t indirect_last;
	uint64_t fork; /* Inode of fork, if existing */
	uint64_t extent_starts[INODE_EXTENTS];
	uint32_t extent_sizes[INODE_EXTENTS];
} __attribute__((packed));

/*
 * Enum containing all attributes of an inode
 * The bits are allocated as such:
 * 0xTTTXXXXXXXXXFFFFFFFFPPPPPPPPPPPP
 * Where P == Posix permissions
 *       F == Filesystem-specific attributes
 *       T == Filetype attributes
 *   and X == Unused
 */
enum inode_attr {
	/* Posix permissions */
	IA_RUSR = 1 << 8,
	IA_WUSR = 1 << 7,
	IA_XUSR = 1 << 6,
	IA_RGRP = 1 << 5,
	IA_WGRP = 1 << 4,
	IA_XGRP = 1 << 3,	
	IA_ROTH = 1 << 2,
	IA_WOTH = 1 << 1,
	IA_XOTH = 1 << 0,
	IA_SUID = 1 << 11, /* Execute as user id */
	IA_SGID = 1 << 10, /* Execute as group id */
	IA_SVTX = 1 << 9, /* Restrict rename/delete to owner */
	/* Filesystem-specific attributes */
	IA_HIDDEN = 1 << 12, /* Do not show in default directory listings */
	IA_SYSTEM = 1 << 13, /* Warn that this is a system file */
	IA_ARCHIVE = 1 << 14, /* File changed since last backup */
	IA_SYNC = 1 << 15, /* Writes must be committed immediately */
	IA_NOATIME = 1 << 16, /* Do not update access time */
	IA_IMMUTABLE = 1 << 17, /* Do not move file sectors */
	/* Keep preallocated sectors beyond inode.size after file is closed */	
	IA_PREALLOC = 1 << 18,
	IA_INLINE = 1 << 19, /* Inline extended attributes in first sector */
	/* Filetype attributes */
	IA_FMT_MASK = 7 << 29, /* Mask of file type */
	IA_FMT_REG = 1 << 29, /* Regular file */
	IA_FMT_DIR = 2 << 29, /* Directory */
	IA_FMT_SYM = 3 << 29, /* Symbolic link */
	IA_FMT_FORK = 4 << 29 /* Fork */
};

/* 
 * A 16-byte entry for a file in a directory
 * dir_entry.name may be longer or shorter than 4 bytes
 * However, the structure must be aligned to 16 bytes
 */
struct dir_entry {
	uint64_t inode;
	uint8_t type; /* Type of the file, see: enum file_type */
	uint8_t entry_length; /* Length of the entry in 16-byte chunks */
	uint16_t name_length; /* Length of the name; may be other than 4 */
	uint8_t name[4]; /* May be larger or smaller than 4 */
} __attribute__((packed));

/* 
 * File type used in dir_entry
 * Analogous to IA_FMT
 */
enum file_type {
	FT_NONE = 0, /* An empty entry */
	FT_REG = IA_FMT_REG >> 29,
	FT_DIR = IA_FMT_DIR >> 29,
	FT_SYM = IA_FMT_SYM >> 29
};

#endif // LEANFS_H
