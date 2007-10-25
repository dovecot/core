#ifndef CRC32_H
#define CRC32_H

uint32_t crc32_data(const void *data, size_t size);
uint32_t crc32_str(const char *str);

#endif
