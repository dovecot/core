#ifndef __BYTEORDER_H
#define __BYTEORDER_H

#ifdef WORDS_BIGENDIAN

/* Bits in network byte order */
#  define NBO32_BIT0	0x00000001
#  define NBO32_BIT1	0x00000002
#  define NBO32_BIT2	0x00000004
#  define NBO32_BIT3	0x00000008
#  define NBO32_BIT4	0x00000010
#  define NBO32_BIT5	0x00000020
#  define NBO32_BIT6	0x00000040
#  define NBO32_BIT7	0x00000080
#  define NBO32_BIT8	0x00000100
#  define NBO32_BIT9	0x00000200
#  define NBO32_BIT10	0x00000400
#  define NBO32_BIT11	0x00000800
#  define NBO32_BIT12	0x00001000
#  define NBO32_BIT13	0x00002000
#  define NBO32_BIT14	0x00004000
#  define NBO32_BIT15	0x00008000
#  define NBO32_BIT16	0x00010000
#  define NBO32_BIT17	0x00020000
#  define NBO32_BIT18	0x00040000
#  define NBO32_BIT19	0x00080000
#  define NBO32_BIT20	0x00100000
#  define NBO32_BIT21	0x00200000
#  define NBO32_BIT22	0x00400000
#  define NBO32_BIT23	0x00800000
#  define NBO32_BIT24	0x01000000
#  define NBO32_BIT25	0x02000000
#  define NBO32_BIT26	0x04000000
#  define NBO32_BIT27	0x08000000
#  define NBO32_BIT28	0x10000000
#  define NBO32_BIT29	0x20000000
#  define NBO32_BIT30	0x40000000
#  define NBO32_BIT31	0x80000000

#  define nbo_to_host(data, size)
#  define host_to_nbo(data, size)
#  define nbo_to_uint32(num) (num)
#  define uint32_to_nbo(num) (num)
#else

/* We support only big endian and little endian. AFAIK PDP-endian is the
   only third used one but I don't think I need PDP-support for now :) */
#include <arpa/inet.h>

/* Bits in network byte order */
#  define NBO32_BIT0	0x01000000
#  define NBO32_BIT1	0x02000000
#  define NBO32_BIT2	0x04000000
#  define NBO32_BIT3	0x08000000
#  define NBO32_BIT4	0x10000000
#  define NBO32_BIT5	0x20000000
#  define NBO32_BIT6	0x40000000
#  define NBO32_BIT7	0x80000000
#  define NBO32_BIT8	0x00010000
#  define NBO32_BIT9	0x00020000
#  define NBO32_BIT10	0x00040000
#  define NBO32_BIT11	0x00080000
#  define NBO32_BIT12	0x00100000
#  define NBO32_BIT13	0x00200000
#  define NBO32_BIT14	0x00400000
#  define NBO32_BIT15	0x00800000
#  define NBO32_BIT16	0x00000100
#  define NBO32_BIT17	0x00000200
#  define NBO32_BIT18	0x00000400
#  define NBO32_BIT19	0x00000800
#  define NBO32_BIT20	0x00001000
#  define NBO32_BIT21	0x00002000
#  define NBO32_BIT22	0x00004000
#  define NBO32_BIT23	0x00008000
#  define NBO32_BIT24	0x00000001
#  define NBO32_BIT25	0x00000002
#  define NBO32_BIT26	0x00000004
#  define NBO32_BIT27	0x00000008
#  define NBO32_BIT28	0x00000010
#  define NBO32_BIT29	0x00000020
#  define NBO32_BIT30	0x00000040
#  define NBO32_BIT31	0x00000080

void nbo_to_host(void *data, size_t size);
void host_to_nbo(void *data, size_t size);

#  define nbo_to_uint32(num) ntohl(num)
#  define uint32_to_nbo(num) htonl(num)
#endif

#endif
