/* Copyright (c) 2010-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "istream.h"
#include "istream-zlib.h"
#include "ostream-zlib.h"
#include "iostream-lz4.h"
#include "compression.h"

#ifndef HAVE_ZLIB
#  define i_stream_create_gz NULL
#  define o_stream_create_gz NULL
#  define i_stream_create_deflate NULL
#  define o_stream_create_deflate NULL
#endif
#ifndef HAVE_BZLIB
#  define i_stream_create_bz2 NULL
#  define o_stream_create_bz2 NULL
#endif
#ifndef HAVE_LZMA
#  define i_stream_create_lzma NULL
#  define o_stream_create_lzma NULL
#endif
#ifndef HAVE_LZ4
#  define i_stream_create_lz4 NULL
#  define o_stream_create_lz4 NULL
#endif
#ifndef HAVE_ZSTD
#  define i_stream_create_zstd NULL
#  define o_stream_create_zstd NULL
#endif

static bool is_compressed_zlib(struct istream *input)
{
	const unsigned char *data;
	size_t size;

	/* Peek in to the stream and see if it looks like it's compressed
	   (based on its header). This also means that users can try to exploit
	   security holes in the uncompression library by APPENDing a specially
	   crafted mail. So let's hope zlib is free of holes. */
	if (i_stream_read_bytes(input, &data, &size, 2) <= 0)
		return FALSE;
	i_assert(size >= 2);

	return data[0] == 31 && data[1] == 139;
}

static bool is_compressed_bzlib(struct istream *input)
{
	const unsigned char *data;
	size_t size;

	if (i_stream_read_bytes(input, &data, &size, 4+6) <= 0)
		return FALSE;
	if (data[0] != 'B' || data[1] != 'Z')
		return FALSE;
	if (data[2] != 'h' && data[2] != '0')
		return FALSE;
	if (data[3] < '1' || data[3] > '9')
		return FALSE;
	return memcmp(data + 4, "\x31\x41\x59\x26\x53\x59", 6) == 0;
}

static bool is_compressed_xz(struct istream *input)
{
	const unsigned char *data;
	size_t size;

	if (i_stream_read_bytes(input, &data, &size, 6) <= 0)
		return FALSE;
	return memcmp(data, "\xfd\x37\x7a\x58\x5a", 6) == 0;
}

static bool is_compressed_lz4(struct istream *input)
{
	const unsigned char *data;
	size_t size;

	if (i_stream_read_bytes(input, &data, &size, IOSTREAM_LZ4_MAGIC_LEN) <= 0)
		return FALSE;
	/* there is no standard LZ4 header, so we've created our own */
	return memcmp(data, IOSTREAM_LZ4_MAGIC, IOSTREAM_LZ4_MAGIC_LEN) == 0;
}

#define ZSTD_MAGICNUMBER            0xFD2FB528    /* valid since v0.8.0 */
static bool is_compressed_zstd(struct istream *input)
{
	const unsigned char *data;
	size_t size = 0;

	if (i_stream_read_bytes(input, &data, &size, sizeof(uint32_t)) <= 0)
	        return FALSE;
	i_assert(size >= sizeof(uint32_t));

	return le32_to_cpu_unaligned(data) == ZSTD_MAGICNUMBER;
}

int compression_lookup_handler(const char *name,
			       const struct compression_handler **handler_r)
{
	unsigned int i;

	for (i = 0; compression_handlers[i].name != NULL; i++) {
		if (strcmp(name, compression_handlers[i].name) == 0) {
			if (compression_handlers[i].create_istream == NULL ||
			    compression_handlers[i].create_ostream == NULL) {
				/* Handler is known but not compiled in */
				return 0;
			}
			(*handler_r) = &compression_handlers[i];
			return 1;
		}
	}
	return -1;
}

const struct compression_handler *
compression_detect_handler(struct istream *input)
{
	unsigned int i;

	for (i = 0; compression_handlers[i].name != NULL; i++) {
		if (compression_handlers[i].is_compressed != NULL &&
		    compression_handlers[i].is_compressed(input))
			return &compression_handlers[i];
	}
	return NULL;
}

const struct compression_handler *
compression_lookup_handler_from_ext(const char *path)
{
	unsigned int i;
	size_t len, path_len = strlen(path);

	for (i = 0; compression_handlers[i].name != NULL; i++) {
		if (compression_handlers[i].ext == NULL)
			continue;

		len = strlen(compression_handlers[i].ext);
		if (path_len > len &&
		    strcmp(path + path_len - len, compression_handlers[i].ext) == 0)
			return &compression_handlers[i];
	}
	return NULL;
}

const struct compression_handler compression_handlers[] = {
	{ "gz", ".gz", is_compressed_zlib,
	  i_stream_create_gz, o_stream_create_gz },
	{ "bz2", ".bz2", is_compressed_bzlib,
	  i_stream_create_bz2, o_stream_create_bz2 },
	{ "deflate", NULL, NULL,
	  i_stream_create_deflate, o_stream_create_deflate },
	{ "xz", ".xz", is_compressed_xz,
	  i_stream_create_lzma, o_stream_create_lzma },
	{ "lz4", ".lz4", is_compressed_lz4,
	  i_stream_create_lz4, o_stream_create_lz4 },
	{ "zstd", ".zstd", is_compressed_zstd,
	  i_stream_create_zstd, o_stream_create_zstd },
	{ NULL, NULL, NULL, NULL, NULL }
};
