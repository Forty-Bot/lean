#include "driver.h"
#include "lean.h"

#include <linux/fs.h>
#include <linux/types.h>

static ssize_t lean_read_iter(struct kiocb *iocb, struct iov_iter *iter)
{
	/* Skip past the inode contained within the first sector */
	iocb->ki_pos += sizeof(struct lean_inode);
	return generic_file_read_iter(iocb, iter);
}

const struct file_operations lean_file_ops = {
	.llseek = generic_file_llseek,
	.read_iter = lean_read_iter,
};
