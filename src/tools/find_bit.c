/* bit search implementation
 *
 * Copied from the linux kernel
 *
 * Copyright (C) 2004 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 *
 * Copyright (C) 2008 IBM Corporation
 * 'find_last_bit' is written by Rusty Russell <rusty@rustcorp.com.au>
 * (Inspired by David Howell's find_next_bit implementation)
 *
 * Rewritten by Yury Norov <yury.norov@gmail.com> to decrease
 * size and improve performance, 2015.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 */
#include "find.h"
#include "user.h"

#include <stddef.h>
#include <strings.h>

#define likely(x) x
#define unlikely(x) x

/*
 * This looks more complex than it should be. But we need to
 * get the type for the ~ right in round_down (it needs to be
 * as wide as the result!), and we want to evaluate the macro
 * arguments just once each.
 */
#define __round_mask(x, y) ((__typeof__(x))((y)-1))
#define round_up(x, y) ((((x)-1) | __round_mask(x, y))+1)
#define round_down(x, y) ((x) & ~__round_mask(x, y))

#define ffs(x) _Generic((x), \
			int: ffs, \
			long: ffsl, \
			long long: ffsll, \
			unsigned: ffs, \
			unsigned long: ffsl, \
			unsigned long long: ffsll)(x)
#define __ffs(x) (ffs(x) - 1)
#define ffz(x) __ffs(~(x))

/*
 * This is a common helper function for find_next_bit, find_next_zero_bit, and
 * find_next_and_bit. The differences are:
 *  - The "invert" argument, which is XORed with each fetched word before
 *    searching it for one bits.
 *  - The optional "addr2", which is anded with "addr1" if present.
 */
static inline size_t _find_next_bit(const size_t *addr1, const size_t *addr2,
				    size_t nbits, size_t start, size_t invert)
{
	size_t tmp;

	if (unlikely(start >= nbits))
		return nbits;

	tmp = addr1[start / BITS_PER_SIZE_T];
	if (addr2)
		tmp &= addr2[start / BITS_PER_SIZE_T];
	tmp ^= invert;

	/* Handle 1st word. */
	tmp &= BITMAP_FIRST_WORD_MASK(start);
	start = round_down(start, BITS_PER_SIZE_T);

	while (!tmp) {
		start += BITS_PER_SIZE_T;
		if (start >= nbits)
			return nbits;

		tmp = addr1[start / BITS_PER_SIZE_T];
		if (addr2)
			tmp &= addr2[start / BITS_PER_SIZE_T];
		tmp ^= invert;
	}

	return min(start + __ffs(tmp), nbits);
}

/*
 * Find the next set bit in a memory region.
 */
size_t find_next_bit(const size_t *addr, size_t size, size_t offset)
{
	return _find_next_bit(addr, NULL, size, offset, 0);
}

/*
 * Find the first set bit in a memory region.
 */
size_t find_first_bit(const size_t *addr, size_t size)
{
	size_t idx;

	for (idx = 0; idx * BITS_PER_SIZE_T < size; idx++) {
		if (addr[idx])
			return min(idx * BITS_PER_SIZE_T + __ffs(addr[idx]),
				   size);
	}

	return size;
}

/*
 * Find the first cleared bit in a memory region.
 */
size_t find_first_zero_bit(const size_t *addr, size_t size)
{
	size_t idx;

	for (idx = 0; idx * BITS_PER_SIZE_T < size; idx++) {
		if (addr[idx] != ~((size_t)0))
			return min(idx * BITS_PER_SIZE_T + ffz(addr[idx]),
				   size);
	}

	return size;
}

size_t find_next_zero_bit(const size_t *addr, size_t size, size_t offset)
{
	return _find_next_bit(addr, NULL, size, offset, ~((size_t)0));
}

size_t find_next_and_bit(const size_t *addr1, const size_t *addr2,
			 size_t size, size_t offset)
{
	return _find_next_bit(addr1, addr2, size, offset, 0);
}
