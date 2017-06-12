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

#ifndef BYTEORDER_H
#define BYTEORDER_H

/*
 * These prototypes exist to catch bugs in the code generating macros below.
 */
/* return byte swapped input */
static inline uint64_t bswap_64(uint64_t in);
static inline uint32_t bswap_32(uint32_t in);
static inline uint16_t bswap_16(uint16_t in);
static inline uint8_t bswap_8(uint8_t in);

/* load an unaligned cpu native endian number from memory */
static inline uint64_t cpu64_to_cpu_unaligned(const void *in);
static inline uint32_t cpu32_to_cpu_unaligned(const void *in);
static inline uint16_t cpu16_to_cpu_unaligned(const void *in);
static inline uint8_t cpu8_to_cpu_unaligned(const void *in);

/* load an unaligned big endian number from memory */
static inline uint64_t be64_to_cpu_unaligned(const void *in);
static inline uint32_t be32_to_cpu_unaligned(const void *in);
static inline uint16_t be16_to_cpu_unaligned(const void *in);
static inline uint8_t be8_to_cpu_unaligned(const void *in);

/* load an unaligned little endian number from memory */
static inline uint64_t le64_to_cpu_unaligned(const void *in);
static inline uint32_t le32_to_cpu_unaligned(const void *in);
static inline uint16_t le16_to_cpu_unaligned(const void *in);
static inline uint8_t le8_to_cpu_unaligned(const void *in);

/* store into memory a cpu native endian number as a big endian number */
static inline void cpu64_to_be_unaligned(uint64_t in, void *out);
static inline void cpu32_to_be_unaligned(uint32_t in, void *out);
static inline void cpu16_to_be_unaligned(uint16_t in, void *out);
static inline void cpu8_to_be_unaligned(uint8_t in, void *out);

/* store into memory a cpu native endian number as a little endian number */
static inline void cpu64_to_le_unaligned(uint64_t in, void *out);
static inline void cpu32_to_le_unaligned(uint32_t in, void *out);
static inline void cpu16_to_le_unaligned(uint16_t in, void *out);
static inline void cpu8_to_le_unaligned(uint8_t in, void *out);

/* convert a big endian input into cpu native endian */
static inline uint64_t be64_to_cpu(uint64_t in);
static inline uint32_t be32_to_cpu(uint32_t in);
static inline uint16_t be16_to_cpu(uint16_t in);
static inline uint8_t be8_to_cpu(uint8_t in);

/* convert a cpu native endian input into big endian */
static inline uint64_t cpu64_to_be(uint64_t in);
static inline uint32_t cpu32_to_be(uint32_t in);
static inline uint16_t cpu16_to_be(uint16_t in);
static inline uint8_t cpu8_to_be(uint8_t in);

/* convert a little endian input into cpu native endian */
static inline uint64_t le64_to_cpu(uint64_t in);
static inline uint32_t le32_to_cpu(uint32_t in);
static inline uint16_t le16_to_cpu(uint16_t in);
static inline uint8_t le8_to_cpu(uint8_t in);

/* convert a cpu native endian input into little endian */
static inline uint64_t cpu64_to_le(uint64_t in);
static inline uint32_t cpu32_to_le(uint32_t in);
static inline uint16_t cpu16_to_le(uint16_t in);
static inline uint8_t cpu8_to_le(uint8_t in);

/*
 * byte swapping
 */
static inline uint64_t bswap_64(uint64_t in)
{
	return ((in & 0xff00000000000000) >> 56) |
	       ((in & 0x00ff000000000000) >> 40) |
	       ((in & 0x0000ff0000000000) >> 24) |
	       ((in & 0x000000ff00000000) >> 8) |
	       ((in & 0x00000000ff000000) << 8) |
	       ((in & 0x0000000000ff0000) << 24) |
	       ((in & 0x000000000000ff00) << 40) |
	       ((in & 0x00000000000000ff) << 56);
}

static inline uint32_t bswap_32(uint32_t in)
{
	return ((in & 0xff000000) >> 24) |
	       ((in & 0x00ff0000) >> 8) |
	       ((in & 0x0000ff00) << 8) |
	       ((in & 0x000000ff) << 24);
}

static inline uint16_t bswap_16(uint16_t in)
{
	return ((in & 0xff00) >> 8) |
	       ((in & 0x00ff) << 8);
}

static inline uint8_t bswap_8(uint8_t in)
{
	return (in & 0xff);
}

/*
 * unaligned big-endian integer
 */
static inline uint64_t be64_to_cpu_unaligned(const void *in)
{
	const uint8_t *p = (const uint8_t *) in;

	return (((uint64_t) p[0] << 56) |
		((uint64_t) p[1] << 48) |
		((uint64_t) p[2] << 40) |
		((uint64_t) p[3] << 32) |
		((uint64_t) p[4] << 24) |
		((uint64_t) p[5] << 16) |
		((uint64_t) p[6] << 8) |
		((uint64_t) p[7]));
}

static inline void cpu64_to_be_unaligned(uint64_t in, void *out)
{
	uint8_t *p = (uint8_t *) out;

	p[0] = (in >> 56) & 0xff;
	p[1] = (in >> 48) & 0xff;
	p[2] = (in >> 40) & 0xff;
	p[3] = (in >> 32) & 0xff;
	p[4] = (in >> 24) & 0xff;
	p[5] = (in >> 16) & 0xff;
	p[6] = (in >> 8) & 0xff;
	p[7] = in & 0xff;
}

static inline uint32_t be32_to_cpu_unaligned(const void *in)
{
	const uint8_t *p = (const uint8_t *) in;

	return (((uint32_t) p[0] << 24) |
		((uint32_t) p[1] << 16) |
		((uint32_t) p[2] << 8) |
		((uint32_t) p[3]));
}

static inline void cpu32_to_be_unaligned(uint32_t in, void *out)
{
	uint8_t *p = (uint8_t *) out;

	p[0] = (in >> 24) & 0xff;
	p[1] = (in >> 16) & 0xff;
	p[2] = (in >> 8) & 0xff;
	p[3] = in & 0xff;
}

static inline uint16_t be16_to_cpu_unaligned(const void *in)
{
	const uint8_t *p = (const uint8_t *) in;

	return (((uint16_t) p[0] << 8) |
		((uint16_t) p[1]));
}

static inline void cpu16_to_be_unaligned(uint16_t in, void *out)
{
	uint8_t *p = (uint8_t *) out;

	p[0] = (in >> 8) & 0xff;
	p[1] = in & 0xff;
}

static inline uint8_t be8_to_cpu_unaligned(const void *in)
{
	return *((const uint8_t *) in);
}

static inline void cpu8_to_be_unaligned(uint8_t in, void *out)
{
	uint8_t *p = (uint8_t *) out;

	*p = in;
}

/*
 * unaligned little-endian & cpu-endian integers
 */
#define __GEN(size, bswap)						\
static inline uint##size##_t le##size##_to_cpu_unaligned(const void *in)\
{									\
	uint##size##_t x = be##size##_to_cpu_unaligned(in);		\
	/* we read a LE int as BE, so we always have to byte swap */	\
	return bswap_##size(x);						\
}									\
static inline void cpu##size##_to_le_unaligned(uint##size##_t in,	\
					       void *out)		\
{									\
	/* we'll be writing in BE, so we always have to byte swap */	\
	cpu##size##_to_be_unaligned(bswap_##size(in), out);		\
}									\
static inline uint##size##_t cpu##size##_to_cpu_unaligned(const void *in)\
{									\
	uint##size##_t x = be##size##_to_cpu_unaligned(in);		\
	return bswap;							\
}

#if WORDS_BIGENDIAN
#define GEN(size)	__GEN(size, x)
#else
#define GEN(size)	__GEN(size, bswap_##size(x))
#endif

GEN(64)
GEN(32)
GEN(16)
GEN(8)

#undef __GEN
#undef GEN

/*
 * byte ordering
 */
#define ___GEN(from, size, to, bswap)					\
static inline uint##size##_t from##size##_to_##to(uint##size##_t x)	\
{									\
	return bswap;							\
}

#if WORDS_BIGENDIAN
#define __GEN(from, size, to, be, le) ___GEN(from, size, to, be)
#else
#define __GEN(from, size, to, be, le) ___GEN(from, size, to, le)
#endif

#define GEN(size)							\
	__GEN(be,  size, cpu, x, bswap_##size(x))			\
	__GEN(cpu, size, be,  x, bswap_##size(x))			\
	__GEN(le,  size, cpu, bswap_##size(x), x)			\
	__GEN(cpu, size, le,  bswap_##size(x), x)

GEN(64)
GEN(32)
GEN(16)
GEN(8)

#undef ___GEN
#undef __GEN
#undef GEN

#endif
