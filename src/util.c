#include "lean.h"

#ifdef __KERNEL__
#include <linux/bug.h>
#define lean_assert WARN_ON
#else // __KERNEL__
#include <assert.h>
#define lean_assert assert
#endif // __KERNEL__

/*
 * Checksum function; does not include the first 4 bytes of the structure
 */
uint32_t lean_checksum(const void *data, size_t size)
{
	size_t i;
	uint32_t res = 0;
	const uint32_t *d = (const uint32_t *) data;
	lean_assert((size & (sizeof(uint32_t) - 1)) == 0);
	
	size /= sizeof(uint32_t);
	for (i = 1; i != size; i++)
		res = (res << 31) + (res >> 1) + d[i];
	return res;
}
