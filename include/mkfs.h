#ifndef MKFS_H
#define MKFS_H

#include <errno.h>
#include <linux/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

static inline int statx(int dirfd, const char *pathname, int flags,
		        unsigned int mask, struct statx *statxbuf)
{
	return syscall(SYS_statx, dirfd, pathname, flags, mask, statxbuf);
}

/* 
 * WARNING: Stomps on cwd and errno!
 * Do not use if you (or anyone else) needs to do file I/O later!
 * For use only immediately before termination.
 */
static inline char *getpath_unsafe(int fd)
{
	if (fchdir(fd) == -1)
		return NULL;
	
	return get_current_dir_name();
}

#endif /* MKFS_H */
