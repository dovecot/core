/* Copyright (C) 2003 Timo Sirainen */

#include "lib.h"
#include "byteorder.h"

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
