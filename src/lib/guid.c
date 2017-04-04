/* Copyright (c) 2011-2017 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "ioloop.h"
#include "buffer.h"
#include "str.h"
#include "sha1.h"
#include "hash.h"
#include "hex-binary.h"
#include "hostpid.h"
#include "guid.h"

#include <unistd.h>
#include <time.h>

const char *guid_generate(void)
{
	static struct timespec ts = { 0, 0 };
	static unsigned int pid = 0;

	/* we'll use the current time in nanoseconds as the initial 64bit
	   counter. */
	if (ts.tv_sec == 0) {
		if (clock_gettime(CLOCK_REALTIME, &ts) < 0)
			i_fatal("clock_gettime() failed: %m");
		pid = getpid();
	} else if ((uint32_t)ts.tv_nsec < (uint32_t)-1) {
		ts.tv_nsec++;
	} else {
		ts.tv_sec++;
		ts.tv_nsec = 0;
	}
	return t_strdup_printf("%08x%08lx.%x.%s",
			       (unsigned int)ts.tv_nsec,
			       (unsigned long)ts.tv_sec,
			       pid, my_hostname);
}

void guid_128_host_hash_get(const char *host,
			    unsigned char hash_r[STATIC_ARRAY GUID_128_HOST_HASH_SIZE])
{
	unsigned char full_hash[SHA1_RESULTLEN];

	sha1_get_digest(host, strlen(host), full_hash);
	memcpy(hash_r, full_hash + sizeof(full_hash)-GUID_128_HOST_HASH_SIZE,
	       GUID_128_HOST_HASH_SIZE);
}

void guid_128_generate(guid_128_t guid_r)
{
#if GUID_128_HOST_HASH_SIZE != 4
#  error GUID_128_HOST_HASH_SIZE must be 4
#endif
	static struct timespec ts = { 0, 0 };
	static uint8_t guid_static[8];
	uint32_t pid;

	/* we'll use the current time in nanoseconds as the initial 64bit
	   counter. */
	if (ts.tv_sec == 0) {
		if (clock_gettime(CLOCK_REALTIME, &ts) < 0)
			i_fatal("clock_gettime() failed: %m");
		pid = getpid();

		guid_static[0] = (pid & 0x000000ff);
		guid_static[1] = (pid & 0x0000ff00) >> 8;
		guid_static[2] = (pid & 0x00ff0000) >> 16;
		guid_static[3] = (pid & 0xff000000) >> 24;
		guid_128_host_hash_get(my_hostdomain(), guid_static+4);
	} else if (ioloop_timeval.tv_sec > ts.tv_sec ||
		   (ioloop_timeval.tv_sec == ts.tv_sec &&
		    ioloop_timeval.tv_usec > ts.tv_nsec*1000)) {
		/* use ioloop's time since we have it. it doesn't provide any
		   more uniqueness, but it allows finding out more reliably
		   when a GUID was created. */
		ts.tv_sec = ioloop_timeval.tv_sec;
		ts.tv_nsec = ioloop_timeval.tv_usec*1000;
	} else if ((uint32_t)ts.tv_nsec < 1000000000) {
		ts.tv_nsec++;
	} else {
		ts.tv_sec++;
		ts.tv_nsec = 0;
	}

	guid_r[0] = (ts.tv_nsec & 0x000000ff);
	guid_r[1] = (ts.tv_nsec & 0x0000ff00) >> 8;
	guid_r[2] = (ts.tv_nsec & 0x00ff0000) >> 16;
	guid_r[3] = (ts.tv_nsec & 0xff000000) >> 24;
	guid_r[4] = (ts.tv_sec & 0x000000ff);
	guid_r[5] = (ts.tv_sec & 0x0000ff00) >> 8;
	guid_r[6] = (ts.tv_sec & 0x00ff0000) >> 16;
	guid_r[7] = (ts.tv_sec & 0xff000000) >> 24;
	memcpy(guid_r + 8, guid_static, 8);
}

bool guid_128_is_empty(const guid_128_t guid)
{
	unsigned int i;

	for (i = 0; i < GUID_128_SIZE; i++) {
		if (guid[i] != 0)
			return FALSE;
	}
	return TRUE;
}

bool guid_128_equals(const guid_128_t guid1, const guid_128_t guid2)
{
	return memcmp(guid1, guid2, GUID_128_SIZE) == 0;
}

int guid_128_from_string(const char *str, guid_128_t guid_r)
{
	buffer_t buf;

	buffer_create_from_data(&buf, guid_r, GUID_128_SIZE);
	return strlen(str) == GUID_128_SIZE*2 &&
		hex_to_binary(str, &buf) == 0 &&
		buf.used == GUID_128_SIZE ? 0 : -1;
}

const char *guid_128_to_string(const guid_128_t guid)
{
	return binary_to_hex(guid, GUID_128_SIZE);
}

unsigned int guid_128_hash(const guid_128_t guid)
{
	return mem_hash(guid, GUID_128_SIZE);
}

int guid_128_cmp(const guid_128_t guid1, const guid_128_t guid2)
{
	return memcmp(guid1, guid2, GUID_128_SIZE);
}

const char *guid_128_to_uuid_string(const guid_128_t guid, enum uuid_format format)
{
	switch(format) {
	case FORMAT_COMPACT:
		return guid_128_to_string(guid);
	case FORMAT_RECORD:
		return t_strdup_printf("%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
				guid[0], guid[1], guid[2], guid[3], guid[4],
				guid[5], guid[6], guid[7], guid[8], guid[9],
				guid[10], guid[11], guid[12], guid[13], guid[14],
				guid[15]);
	case FORMAT_MICROSOFT:
		return t_strdup_printf("{%s}", guid_128_to_uuid_string(guid, FORMAT_RECORD));
	}
	i_unreached();
}

int guid_128_from_uuid_string(const char *str, guid_128_t guid_r)
{
	size_t i,len,m=0;
	int ret;
	T_BEGIN {
		len = strlen(str);
		string_t *str2 = t_str_new(len);
		for(i=0; i < len; i++) {
			/* Microsoft format */
			if (i==0 && str[i] == '{') { m=1; continue; }
			else if (i == len-1 && str[i] == '}') continue;
			/* 8-4-4-4-12 */
			if (((i==8+m) || (i==13+m) || (i==18+m) || (i==23+m)) &&
			    str[i] == '-') continue;
			str_append_c(str2, str[i]);
		}
		ret = guid_128_from_string(str_c(str2), guid_r);
	} T_END;

	return ret;
}
