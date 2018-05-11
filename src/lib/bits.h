#ifndef BITS_H
#define BITS_H

#define UINT64_SUM_OVERFLOWS(a, b) \
	(a > (uint64_t)-1 - b)

#define BIT(n) (1u << (n))

/* These expressions make it easy to ensure that bit test expressions
   are boolean in order to satisfy the in-house -Wstrict-bool. */
/* ((val & bits) == 0) is very common */
#define HAS_NO_BITS(val,bits) (((val) & (bits)) == 0)
/* ((val & bits) != 0) is even more common */
/* Note - illogical behaviour if bits==0, fixing that requires potential
   multiple evaluation, but it's a corner case that should never occur. */
#define HAS_ANY_BITS(val,bits) (((val) & (bits)) != 0)
/* ((val & bits) == bits) is uncommon */
#define HAS_ALL_BITS(val,bits) ((~(val) & (bits)) == 0)

/* Returns x, such that x is the smallest power of 2 >= num. */
size_t nearest_power(size_t num) ATTR_CONST;

/* Returns TRUE if 2^x=num, i.e. if num has only a single bit set to 1. */
static inline bool ATTR_CONST
bits_is_power_of_two(uint64_t num)
{
	return num > 0 && (num & (num - 1)) == 0;
}

#if __GNUC__ > 3 || (__GNUC__ == 3 && __GNUC_MINOR__ >= 4)
static inline unsigned int ATTR_CONST
bits_required32(uint32_t num)
{
	return num == 0 ? 0 : 32 - __builtin_clz(num);
}
static inline unsigned int ATTR_CONST
bits_required8(uint8_t num)   { return bits_required32(num); }

static inline unsigned int ATTR_CONST
bits_required16(uint16_t num) { return bits_required32(num); }

static inline unsigned int ATTR_CONST
bits_required64(uint64_t num)
{
	return num == 0 ? 0 : 64 - __builtin_clzll(num);
}
#else
unsigned int bits_required8(uint8_t num) ATTR_CONST;

static inline
unsigned int bits_required16(uint16_t num)
{
	return (num <= 0xff) ? bits_required8(num)
		: 8 + bits_required8(num >> 8);
}
static inline
unsigned int bits_required32(uint32_t num)
{
	return (num <= 0xffff) ? bits_required16(num)
		: 16 + bits_required16(num >> 16);
}
static inline
unsigned int bits_required64(uint64_t num)
{
	return (num <= 0xffffffff) ? bits_required32(num)
		: 32 + bits_required32(num >> 32);
}
#endif

static inline uint64_t
bits_rotl64(uint64_t num, unsigned int count)
{
	const unsigned int mask = CHAR_BIT*sizeof(num) - 1;
	count &= mask;
	return (num << count) | (num >> (-count & mask));
}

static inline uint32_t
bits_rotl32(uint32_t num, unsigned int count)
{
        const unsigned int mask = CHAR_BIT*sizeof(num) - 1;
        count &= mask;
        return (num << count) | (num >> (-count & mask));
}

static inline uint64_t
bits_rotr64(uint64_t num, unsigned int count)
{
	const unsigned int mask = CHAR_BIT*sizeof(num) - 1;
	count &= mask;
	return (num >> count) | (num << (-count & mask));
}

static inline uint32_t
bits_rotr32(uint32_t num, unsigned int count)
{
	const unsigned int mask = CHAR_BIT*sizeof(num) - 1;
	count &= mask;
	return (num >> count) | (num << (-count & mask));
}

/* These functions look too big to be inline, but in almost all expected
   uses, 'fracbits' will be a compile-time constant, and most of the
   expressions will simplify greatly.
*/

/* Perform a piecewise-linear approximation to a log2, with fracbits "fractional" bits.
   Best explained with examples:
   With 2 fractional bits splitting each power of 2 into 4 bands:
     00,   01,   10,   11 ->   00,   01,   10,   11 (small corner cases)
    100,  101,  110,  111 ->  100,  101,  110,  111 ([4-8) split into 4 bands)
   1000, 1001, 1010, 1011 -> 1000, 1000, 1001, 1001 ([8-15) split ...
   1100, 1101, 1110, 1111 -> 1010, 1010, 1011, 1011  ... into 4 bands)
   [16..31) -> 11bb
   [32..63) -> 100bb
   [64..127) -> 101bb
   [128..255) -> 110bb
   e.g. 236 = 11101100 -> ((8-2)<<2 == 11000) + (111.....>> 5 == 111) - 100 == 11011
 */
static inline unsigned int ATTR_CONST
bits_fraclog(unsigned int val, unsigned int fracbits)
{
	unsigned bits = bits_required32(val);
	if (bits <= fracbits + 1)
		return val;

	unsigned int bandnum = bits - fracbits;
	unsigned int bandstart = bandnum << fracbits;
	unsigned int fracoffsbad = val >> (bandnum - 1); /* has leading 1 still */
	unsigned int bucket = bandstart + fracoffsbad - BIT(fracbits);
	return bucket;
}
static inline unsigned int ATTR_CONST
bits_fraclog_bucket_start(unsigned int bucket, unsigned int fracbits)
{
	unsigned int bandnum = bucket >> fracbits;
	if (bandnum <= 1)
		return bucket;
	if (fracbits == 0)
		return BIT(bucket - 1);
	unsigned int fracoffs = bucket & (BIT(fracbits)-1);
	unsigned int fracoffs1 = BIT(fracbits) + fracoffs;
	unsigned int bandstart = fracoffs1 << (bandnum - 1);
	return bandstart;
}
static inline unsigned int ATTR_CONST
bits_fraclog_bucket_end(unsigned int bucket, unsigned int fracbits)
{
	unsigned int bandnum = bucket >> fracbits;
	if (bandnum <= 1)
		return bucket;
	if (fracbits == 0)
		return BIT(bucket - 1) * 2 - 1;
	unsigned int fracoffs = bucket & (BIT(fracbits)-1);
	unsigned int nextfracoffs1 = 1 + BIT(fracbits) + fracoffs;
	unsigned int nextbandstart = nextfracoffs1 << (bandnum - 1);
	return nextbandstart - 1;
}
/* UNSAFE: multiple use of parameter (but expecting a constant in reality).
   But a macro as it's most likely to be used to declare an array size.
*/
#define BITS_FRACLOG_BUCKETS(bits) ((33u - (bits)) << (bits))

#endif
