#ifndef CRC32_H
#define CRC32_H

#define CRC32_INIT 0

uint32_t crc32_data(const void *data, size_t size) ATTR_PURE;
uint32_t crc32_data_more(uint32_t crc, const void *data, size_t size) ATTR_PURE;

static inline uint32_t crc32_str(const char *str)
{
	return crc32_data_more(CRC32_INIT, str, strlen(str));
}
static inline uint32_t crc32_str_more(uint32_t crc, const char *str)
{
	return crc32_data_more(crc, str, strlen(str));
}

#endif
