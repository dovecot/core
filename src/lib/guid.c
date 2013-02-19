/* Copyright (c) 2011-2013 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "buffer.h"
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
	return t_strdup_printf("%04x%04lx%04x%s",
			       (unsigned int)ts.tv_nsec,
			       (unsigned long)ts.tv_sec,
			       pid, my_hostname);
}

void guid_128_host_hash_get(const char *host,
			    unsigned char hash_r[GUID_128_HOST_HASH_SIZE])
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
	} else if ((uint32_t)ts.tv_nsec < (uint32_t)-1) {
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

unsigned int guid_128_hash(const uint8_t *guid)
{
	return mem_hash(guid, GUID_128_SIZE);
}

int guid_128_cmp(const uint8_t *guid1, const uint8_t *guid2)
{
	return memcmp(guid1, guid2, GUID_128_SIZE);
}
