#ifndef MKFS_H
#define MKFS_H

#include <errno.h>
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

#endif /* MKFS_H */
