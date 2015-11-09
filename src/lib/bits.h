#ifndef BITS_H
#define BITS_H

#define UINT64_SUM_OVERFLOWS(a, b) \
	(a > (uint64_t)-1 - b)

#define BIT(n) (1u << (n))

size_t nearest_power(size_t num) ATTR_CONST;

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
