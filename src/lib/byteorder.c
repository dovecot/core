/* Copyright (C) 2003 Timo Sirainen */

#include "lib.h"
#include "byteorder.h"

uint32_t nbo32_bitmasks[32] = {
	NBO32_BIT0, NBO32_BIT1, NBO32_BIT2, NBO32_BIT3,
	NBO32_BIT4, NBO32_BIT5, NBO32_BIT6, NBO32_BIT7,
	NBO32_BIT8, NBO32_BIT9, NBO32_BIT10, NBO32_BIT11,
	NBO32_BIT12, NBO32_BIT13, NBO32_BIT14, NBO32_BIT15,
	NBO32_BIT16, NBO32_BIT17, NBO32_BIT18, NBO32_BIT19,
	NBO32_BIT20, NBO32_BIT21, NBO32_BIT22, NBO32_BIT23,
	NBO32_BIT24, NBO32_BIT25, NBO32_BIT26, NBO32_BIT27,
	NBO32_BIT28, NBO32_BIT29, NBO32_BIT30, NBO32_BIT31
};

#ifndef WORDS_BIGENDIAN

void nbo_to_host(void *data, size_t size)
{
	if (size == sizeof(uint32_t)) {
		uint32_t *num = (uint32_t *) data;

		*num = ntohl(*num);
	} else if (size == sizeof(uint32_t)*2) {
		uint32_t *num = (uint32_t *) data;
		uint32_t temp;

		temp = ntohl(num[0]);
		num[0] = ntohl(num[1]);
		num[1] = temp;
	}
}

void host_to_nbo(void *data, size_t size)
{
	if (size == sizeof(uint32_t)) {
		uint32_t *num = (uint32_t *) data;

		*num = htonl(*num);
	} else if (size == sizeof(uint32_t)*2) {
		uint32_t *num = (uint32_t *) data;
		uint32_t temp;

		temp = htonl(num[0]);
		num[0] = htonl(num[1]);
		num[1] = temp;
	}
}
#endif
