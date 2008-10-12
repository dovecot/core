#ifndef CRC32_H
#define CRC32_H

uint32_t crc32_data(const void *data, size_t size) ATTR_PURE;
uint32_t crc32_str(const char *str) ATTR_PURE;

uint32_t crc32_data_more(uint32_t crc, const void *data, size_t size) ATTR_PURE;
uint32_t crc32_str_more(uint32_t crc, const char *str) ATTR_PURE;

#endif
