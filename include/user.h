#ifndef USER_H
#define USER_H

#include "lean.h"

#include <errno.h>
#include <fts.h>
#include <linux/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

static inline int statx(int dirfd, const char *pathname, int flags,
		        unsigned int mask, struct statx *statxbuf)
{
	return syscall(SYS_statx, dirfd, pathname, flags, mask, statxbuf);
}

static inline loff_t copy_file_range(int fd_in, loff_t *off_in, int fd_out,
				     loff_t *off_out, size_t len,
				     unsigned int flags)
{
	return syscall(__NR_copy_file_range, fd_in, off_in, fd_out, off_out,
		       len, flags);
}

/* Note to implementers: use errno to return errors */
uint64_t alloc_sectors(struct lean_sb_info *sbi, uint64_t goal,
		       uint32_t *count);
int write_inode(struct lean_sb_info *sbi, struct lean_ino_info *li);
struct lean_ino_info *create_inode_stat(struct lean_sb_info *sbi,
				   struct statx *stat);
int add_link(struct lean_sb_info *sbi, struct lean_ino_info *dir,
		  struct lean_ino_info *inode);

uint64_t extend_inode(struct lean_sb_info *sbi, struct lean_ino_info *li,
		      uint32_t *count);
void create_dotfiles(struct lean_sb_info *sbi, struct lean_ino_info *parent,
		     struct lean_ino_info *dir);
int write_inode(struct lean_sb_info *sbi, struct lean_ino_info *li);
struct lean_ino_info *create_inode_ftsent(struct lean_sb_info *sbi, FTSENT *f);
struct lean_ino_info *create_file(struct lean_sb_info *sbi, FTSENT *f);
struct lean_ino_info *create_dir(struct lean_sb_info *sbi, FTS *fts, FTSENT *f);

static inline int put_inode(struct lean_sb_info *sbi, struct lean_ino_info *li)
{
	int ret = write_inode(sbi, li);
	
	free(li);
	return ret;
}

#endif /* USER_H */
