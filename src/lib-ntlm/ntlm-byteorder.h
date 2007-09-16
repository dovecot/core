/*
 * Little-endian data access functions.
 *
 * Copyright (c) 2004 Andrey Panin <pazke@donpac.ru>
 *
 * This software is released under the MIT license.
 */

#ifndef NTLM_BYTEORDER_H
#define NTLM_BYTEORDER_H

#if defined(__i386__) || defined(__x86_64__) || defined(__vax__)

static inline uint16_t read_le16(const void *addr)
{
	return *((const uint16_t *) addr);
}

static inline uint32_t read_le32(const void *addr)
{
	return *((const uint32_t *) addr);
}

static inline uint64_t read_le64(const void *addr)
{
	return *((const uint64_t *) addr);
}

static inline void write_le16(void *addr, const uint16_t value)
{
	*((uint16_t *) addr) = value;
}

static inline void write_le32(void *addr, const uint32_t value)
{
	*((uint32_t *) addr) = value;
}

static inline void write_le64(void *addr, const uint64_t value)
{
	*((uint64_t *) addr) = value;
}

#else

/*
 * Dumb and slow, but byteorder and alignment independent code.
 */

#define readb(addr, pos, type) ((type)(*(((uint8_t *) (addr)) + (pos))))

static inline uint16_t read_le16(const void *addr)
{
	return readb(addr, 0, uint16_t) | (readb(addr, 1, uint16_t) << 8);
}

static inline uint32_t read_le32(const void *addr)
{
	return   readb(addr, 0, uint32_t) |
		(readb(addr, 1, uint32_t) << 8) |
		(readb(addr, 2, uint32_t) << 16) |
		(readb(addr, 3, uint32_t) << 24);
}

static inline uint64_t read_le64(const void *addr)
{
	return   readb(addr, 0, uint64_t) |
		(readb(addr, 1, uint64_t) << 8) |
		(readb(addr, 2, uint64_t) << 16) |
		(readb(addr, 3, uint64_t) << 24) |
		(readb(addr, 4, uint64_t) << 32) |
		(readb(addr, 5, uint64_t) << 40) |
		(readb(addr, 6, uint64_t) << 48) |
		(readb(addr, 7, uint64_t) << 56);
}

#define writeb(addr, pos, value) \
	*(((uint8_t *)(addr)) + (pos)) = (uint8_t) (value)

static inline void write_le16(void *addr, const uint16_t value)
{
	writeb(addr, 0, value & 0xff);
	writeb(addr, 1, (value >> 8) & 0xff);
}

static inline void write_le32(void *addr, const uint32_t value)
{
	writeb(addr, 0, value & 0xff);
	writeb(addr, 1, (value >> 8) & 0xff);
	writeb(addr, 2, (value >> 16) & 0xff);
	writeb(addr, 3, (value >> 24) & 0xff);
}

static inline void write_le64(void *addr, const uint64_t value)
{
	writeb(addr, 0, value & 0xff);
	writeb(addr, 1, (value >> 8) & 0xff);
	writeb(addr, 2, (value >> 16) & 0xff);
	writeb(addr, 3, (value >> 24) & 0xff);
	writeb(addr, 4, (value >> 32) & 0xff);
	writeb(addr, 5, (value >> 40) & 0xff);
	writeb(addr, 6, (value >> 48) & 0xff);
	writeb(addr, 7, (value >> 56) & 0xff);
}

#endif

#endif
