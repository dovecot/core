/*
 * Copyright (c) 2016-2017 Josef 'Jeff' Sipek <jeffpc@josefsipek.net>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include "test-lib.h"
#include "byteorder.h"

struct bswap_run {
	uint64_t in;
	uint8_t out8;
	uint16_t out16;
	uint32_t out32;
	uint64_t out64;
};

static const struct bswap_run runs[] = {
	{
		.in	= 0,
		.out8	= 0,
		.out16	= 0,
		.out32	= 0,
		.out64	= 0,
	},
	{
		.in	= 0xffffffffffffffff,
		.out8	= 0xff,
		.out16	= 0xffff,
		.out32	= 0xffffffff,
		.out64	= 0xffffffffffffffff,
	},
	{
		.in	= 0x123456789abcdef0,
		.out8	= 0xf0,
		.out16	= 0xf0de,
		.out32	= 0xf0debc9a,
		.out64	= 0xf0debc9a78563412,
	},
	{
		.in	= 0x8080808080808080,
		.out8	= 0x80,
		.out16	= 0x8080,
		.out32	= 0x80808080,
		.out64	= 0x8080808080808080,
	},
};

#define CHECK(iter, size, in, exp)					\
	do {								\
		uint##size##_t got = i_bswap_##size(in);			\
									\
		test_begin(t_strdup_printf("byteorder - bswap "		\
					   "(size:%-2u iter:%u)",	\
					   size, iter));		\
		test_assert(got == exp);				\
		test_end();						\
	} while (0)

static void __test(int iter, const struct bswap_run *run)
{
	CHECK(iter, 8, run->in & 0xff, run->out8);
	CHECK(iter, 16, run->in & 0xffff, run->out16);
	CHECK(iter, 32, run->in & 0xffffffff, run->out32);
	CHECK(iter, 64, run->in, run->out64);
}

static void test_bswap(void)
{
	unsigned int i;

	for (i = 0; i < N_ELEMENTS(runs) ; i++)
		__test(i, &runs[i]);
}

struct unaligned_run {
	uint8_t in[8];

	/* outputs */
	uint8_t be8;
	uint16_t be16;
	uint32_t be32;
	uint64_t be64;

	uint8_t le8;
	uint16_t le16;
	uint32_t le32;
	uint64_t le64;

#ifdef WORDS_BIGENDIAN
#define cpu8 be8
#define cpu16 be16
#define cpu32 be32
#define cpu64 be64
#else
#define cpu8 le8
#define cpu16 le16
#define cpu32 le32
#define cpu64 le64
#endif
};

static const struct unaligned_run uruns[] = {
	{
		.in	= {
			0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00,
		},
		.be8	= 0,
		.be16	= 0,
		.be32	= 0,
		.be64	= 0,
		.le8	= 0,
		.le16	= 0,
		.le32	= 0,
		.le64	= 0,
	},
	{
		.in	= {
			0xff, 0xff, 0xff, 0xff,
			0xff, 0xff, 0xff, 0xff,
		},
		.be8	= 0xff,
		.be16	= 0xffff,
		.be32	= 0xffffffff,
		.be64	= 0xffffffffffffffff,
		.le8	= 0xff,
		.le16	= 0xffff,
		.le32	= 0xffffffff,
		.le64	= 0xffffffffffffffff,
	},
	{
		.in	= {
			0x12, 0x34, 0x56, 0x78,
			0x9a, 0xbc, 0xde, 0xf0,
		},
		.be8	= 0x12,
		.be16	= 0x1234,
		.be32	= 0x12345678,
		.be64	= 0x123456789abcdef0,
		.le8	= 0x12,
		.le16	= 0x3412,
		.le32	= 0x78563412,
		.le64	= 0xf0debc9a78563412,
	},
	{
		.in	= {
			0x80, 0x80, 0x80, 0x80,
			0x80, 0x80, 0x80, 0x80,
		},
		.be8	= 0x80,
		.be16	= 0x8080,
		.be32	= 0x80808080,
		.be64	= 0x8080808080808080,
		.le8	= 0x80,
		.le16	= 0x8080,
		.le32	= 0x80808080,
		.le64	= 0x8080808080808080,
	},
};

#define __CHECK_READ(iter, size, pfx, in, fxn, exp)			\
	do {								\
		uint##size##_t got = fxn(in);				\
									\
		test_begin(t_strdup_printf("byteorder - unaligned read "\
					   "(%-3s size:%-2u iter:%u)",	\
					   pfx, size, iter));		\
		test_assert(got == exp);				\
		test_end();						\
	} while (0)

#define CHECK_READ(iter, size, in, be_exp, le_exp, cpu_exp)		\
	do {								\
		__CHECK_READ(iter, size, "BE", in,			\
			     be##size##_to_cpu_unaligned, be_exp);	\
		__CHECK_READ(iter, size, "LE", in,			\
			     le##size##_to_cpu_unaligned, le_exp);	\
		__CHECK_READ(iter, size, "CPU", in,			\
			     cpu##size##_to_cpu_unaligned, cpu_exp);	\
	} while (0)

static void __test_read(int iter, const struct unaligned_run *run)
{
	CHECK_READ(iter, 8, run->in, run->be8, run->le8, run->cpu8);
	CHECK_READ(iter, 16, run->in, run->be16, run->le16, run->cpu16);
	CHECK_READ(iter, 32, run->in, run->be32, run->le32, run->cpu32);
	CHECK_READ(iter, 64, run->in, run->be64, run->le64, run->cpu64);
}

#define __CHECK_WRITE(iter, size, pfx, in, fxn, exp)			\
	do {								\
		uint8_t got[size / 8];					\
									\
		fxn(in, got);						\
									\
		test_begin(t_strdup_printf("byteorder - unaligned write "\
					   "(%-3s size:%-2u iter:%u)",	\
					   pfx, size, iter));		\
		test_assert(memcmp(got, exp, sizeof(got)) == 0);	\
		test_end();						\
	} while (0)

#define CHECK_WRITE(iter, size, out, be_in, le_in)			\
	do {								\
		__CHECK_WRITE(iter, size, "BE", be_in,			\
			      cpu##size##_to_be_unaligned, out);	\
		__CHECK_WRITE(iter, size, "LE", le_in,			\
			      cpu##size##_to_le_unaligned, out);	\
	} while (0)

static void __test_write(int iter, const struct unaligned_run *run)
{
	CHECK_WRITE(iter, 8, run->in, run->be8, run->le8);
	CHECK_WRITE(iter, 16, run->in, run->be16, run->le16);
	CHECK_WRITE(iter, 32, run->in, run->be32, run->le32);
	CHECK_WRITE(iter, 64, run->in, run->be64, run->le64);
}

static void test_unaligned(void)
{
	unsigned int i;

	for (i = 0; i < N_ELEMENTS(uruns) ; i++)
		__test_read(i, &uruns[i]);

	for (i = 0; i < N_ELEMENTS(uruns) ; i++)
		__test_write(i, &uruns[i]);
}

void test_byteorder(void)
{
	test_bswap();
	test_unaligned();
}
