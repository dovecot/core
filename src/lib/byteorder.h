#ifndef __BYTEORDER_H
#define __BYTEORDER_H

#ifdef WORDS_BIGENDIAN
#  define nbo_to_uint32(num) (num)
#  define uint32_to_nbo(num) (num)
#  define nbo_to_uint64(num) (num)
#  define uint64_to_nbo(num) (num)
#else

#include <arpa/inet.h>

#  define nbo_to_uint32(num) ntohl(num)
#  define uint32_to_nbo(num) htonl(num)

uint64_t nbo_to_uint64(uint64_t num);
uint64_t uint64_to_nbo(uint64_t num);
#endif

#endif
