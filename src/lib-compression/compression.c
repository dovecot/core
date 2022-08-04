/* Copyright (c) 2010-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "istream.h"
#include "istream-zlib.h"
#include "ostream-zlib.h"
#include "iostream-lz4.h"
#include "compression.h"

#ifndef HAVE_BZLIB
#  define i_stream_create_bz2 NULL
#  define o_stream_create_bz2 NULL
#  define compression_get_min_level_bz2 NULL
#  define compression_get_default_level_bz2 NULL
#  define compression_get_max_level_bz2 NULL
#endif
#ifndef HAVE_LZ4
#  define i_stream_create_lz4 NULL
#  define o_stream_create_lz4 NULL
#  define compression_get_min_level_lz4 NULL
#  define compression_get_default_level_lz4 NULL
#  define compression_get_max_level_lz4 NULL
#endif
#ifndef HAVE_ZSTD
#  define i_stream_create_zstd NULL
#  define o_stream_create_zstd NULL
#  define compression_get_min_level_zstd NULL
#  define compression_get_default_level_zstd NULL
#  define compression_get_max_level_zstd NULL
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

	if (i_stream_read_bytes(input, &data, &size, 4) <= 0)
		return FALSE;
	if (memcmp(data, "BZh", 3) != 0)
		return FALSE;
	if (data[3] < '1' || data[3] > '9')
		return FALSE;
	/* The above is enough to be considered as the bzlib magic.
	   Normally it's followed by data header beginning with 0x31. However,
	   with empty compressed files it's followed by 0x17. */
	return TRUE;
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

int compression_lookup_handler_from_ext(const char *path,
					const struct compression_handler **handler_r)
{
	unsigned int i;
	size_t len, path_len = strlen(path);

	for (i = 0; compression_handlers[i].name != NULL; i++) {
		if (compression_handlers[i].ext == NULL)
			continue;

		len = strlen(compression_handlers[i].ext);
		if (path_len > len &&
		    strcmp(path + path_len - len, compression_handlers[i].ext) == 0) {
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

const struct compression_handler compression_handlers[] = {
	{
		.name = "gz",
		.ext = ".gz",
		.is_compressed = is_compressed_zlib,
		.create_istream = i_stream_create_gz,
		.create_ostream = o_stream_create_gz,
		.get_min_level = compression_get_min_level_gz,
		.get_default_level = compression_get_default_level_gz,
		.get_max_level = compression_get_max_level_gz,
	},
	{
		.name = "bz2",
		.ext = ".bz2",
		.is_compressed = is_compressed_bzlib,
		.create_istream = i_stream_create_bz2,
		.create_ostream = o_stream_create_bz2,
		.get_min_level = compression_get_min_level_bz2,
		.get_default_level = compression_get_default_level_bz2,
		.get_max_level = compression_get_max_level_bz2,
	},
	{
		.name = "deflate",
		.ext = NULL,
		.is_compressed = NULL,
		.create_istream = i_stream_create_deflate,
		.create_ostream = o_stream_create_deflate,
		.get_min_level = compression_get_min_level_gz,
		.get_default_level = compression_get_default_level_gz,
		.get_max_level = compression_get_max_level_gz,
	},
	{
		.name = "lz4",
		.ext = ".lz4",
		.is_compressed = is_compressed_lz4,
		.create_istream = i_stream_create_lz4,
		.create_ostream = o_stream_create_lz4,
		.get_min_level = compression_get_min_level_lz4, /* does not actually support any of this */
		.get_default_level = compression_get_default_level_lz4,
		.get_max_level = compression_get_max_level_lz4,
	},
	{
		.name = "zstd",
		.ext = ".zstd",
		.is_compressed = is_compressed_zstd,
		.create_istream = i_stream_create_zstd,
		.create_ostream = o_stream_create_zstd,
		.get_min_level = compression_get_min_level_zstd,
		.get_default_level = compression_get_default_level_zstd,
		.get_max_level = compression_get_max_level_zstd,
	},
	{
		.name = "unsupported",
	},
	{
		.name = NULL,
	}
};
