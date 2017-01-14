#include "leanfs.h"

#include <assert.h>
#include <stdlib.h>

/*
 * Checksum function; does not include the first 4 bytes of the structure
 */
uint32_t checksum(const void* data, size_t size)
{
	uint32_t res = 0;
	const uint32_t* d = (const uint32_t *) data;
	assert((size & (sizeof(uint32_t) - 1)) == 0);
	size /= sizeof(uint32_t);
	for (size_t i = 1; i != size; ++i)
		res = (res << 31) + (res >> 1) + d[i];
	return res;
}
