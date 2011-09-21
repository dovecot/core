/* Copyright (c) 2010-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"

#ifdef HAVE_ZLIB

#include "crc32.h"
#include "ostream-private.h"
#include "ostream-zlib.h"
#include <zlib.h>

#define CHUNK_SIZE (1024*32)
#define ZLIB_OS_CODE 0x03  /* Unix */

struct zlib_ostream {
	struct ostream_private ostream;
	z_stream zs;

	unsigned char gz_header[10];
	unsigned char outbuf[CHUNK_SIZE];

	uint32_t crc, bytes32;

	unsigned int gz:1;
	unsigned int header_sent:1;
	unsigned int flushed:1;
};

static void o_stream_zlib_close(struct iostream_private *stream)
{
	struct zlib_ostream *zstream = (struct zlib_ostream *)stream;

	o_stream_flush(&zstream->ostream.ostream);
	(void)deflateEnd(&zstream->zs);
}

static int o_stream_zlib_send_gz_header(struct zlib_ostream *zstream)
{
	ssize_t ret;

	ret = o_stream_send(zstream->ostream.parent, zstream->gz_header,
			    sizeof(zstream->gz_header));
	if ((size_t)ret != sizeof(zstream->gz_header)) {
		o_stream_copy_error_from_parent(&zstream->ostream);
		return -1;
	}
	zstream->header_sent = TRUE;
	return 0;
}

static int o_stream_zlib_lsb_uint32(struct ostream *output, uint32_t num)
{
	unsigned char buf[sizeof(uint32_t)];
	unsigned int i;

	for (i = 0; i < sizeof(buf); i++) {
		buf[i] = num & 0xff;
		num >>= 8;
	}
	if (o_stream_send(output, buf, sizeof(buf)) != sizeof(buf))
		return -1;
	return 0;
}

static int o_stream_zlib_send_gz_trailer(struct zlib_ostream *zstream)
{
	struct ostream *output = zstream->ostream.parent;

	if (!zstream->gz)
		return 0;

	if (o_stream_zlib_lsb_uint32(output, zstream->crc) < 0 ||
	    o_stream_zlib_lsb_uint32(output, zstream->bytes32) < 0) {
		o_stream_copy_error_from_parent(&zstream->ostream);
		return -1;
	}
	return 0;
}

static int
o_stream_zlib_send_chunk(struct zlib_ostream *zstream,
			 const void *data, size_t size)
{
	z_stream *zs = &zstream->zs;
	ssize_t ret;
	int flush;

	flush = zstream->ostream.corked || zstream->gz ?
		Z_NO_FLUSH : Z_SYNC_FLUSH;

	if (!zstream->header_sent)
		o_stream_zlib_send_gz_header(zstream);

	zs->next_in = (void *)data;
	zs->avail_in = size;
	while (zs->avail_in > 0) {
		if (zs->avail_out == 0) {
			zs->next_out = zstream->outbuf;
			zs->avail_out = sizeof(zstream->outbuf);

			ret = o_stream_send(zstream->ostream.parent,
					    zstream->outbuf,
					    sizeof(zstream->outbuf));
			if (ret != (ssize_t)sizeof(zstream->outbuf)) {
				o_stream_copy_error_from_parent(&zstream->ostream);
				return -1;
			}
		}

		switch (deflate(zs, flush)) {
		case Z_OK:
		case Z_BUF_ERROR:
			break;
		default:
			i_unreached();
		}
	}
	zstream->crc = crc32_data_more(zstream->crc, data, size);
	zstream->bytes32 += size;
	zstream->flushed = flush == Z_SYNC_FLUSH &&
		zs->avail_out == sizeof(zstream->outbuf);
	return 0;
}

static int o_stream_zlib_send_flush(struct zlib_ostream *zstream)
{
	z_stream *zs = &zstream->zs;
	unsigned int len;
	bool done = FALSE;
	int ret;

	i_assert(zs->avail_in == 0);

	if (zstream->flushed)
		return 0;
	if (!zstream->header_sent)
		o_stream_zlib_send_gz_header(zstream);

	do {
		len = sizeof(zstream->outbuf) - zs->avail_out;
		if (len != 0) {
			zs->next_out = zstream->outbuf;
			zs->avail_out = sizeof(zstream->outbuf);

			ret = o_stream_send(zstream->ostream.parent,
					    zstream->outbuf, len);
			if (ret != (int)len) {
				o_stream_copy_error_from_parent(&zstream->ostream);
				return -1;
			}
			if (done)
				break;
		}

		switch (deflate(zs, zstream->gz ? Z_FINISH : Z_SYNC_FLUSH)) {
		case Z_OK:
		case Z_BUF_ERROR:
			break;
		case Z_STREAM_END:
			done = TRUE;
			break;
		default:
			i_unreached();
		}
	} while (zs->avail_out != sizeof(zstream->outbuf));

	if (o_stream_zlib_send_gz_trailer(zstream) < 0)
		return -1;
	zstream->flushed = TRUE;
	return 0;
}

static int o_stream_zlib_flush(struct ostream_private *stream)
{
	struct zlib_ostream *zstream = (struct zlib_ostream *)stream;
	int ret;

	if (o_stream_zlib_send_flush(zstream) < 0)
		return -1;

	ret = o_stream_flush(stream->parent);
	if (ret < 0)
		o_stream_copy_error_from_parent(stream);
	return ret;
}

static ssize_t
o_stream_zlib_sendv(struct ostream_private *stream,
		    const struct const_iovec *iov, unsigned int iov_count)
{
	struct zlib_ostream *zstream = (struct zlib_ostream *)stream;
	ssize_t bytes = 0;
	unsigned int i;

	for (i = 0; i < iov_count; i++) {
		if (o_stream_zlib_send_chunk(zstream, iov[i].iov_base,
					     iov[i].iov_len) < 0)
			return -1;
		bytes += iov[i].iov_len;
	}
	stream->ostream.offset += bytes;

	if (!zstream->ostream.corked) {
		if (o_stream_zlib_send_flush(zstream) < 0)
			return -1;
	}
	return bytes;
}

static void o_stream_zlib_init_gz_header(struct zlib_ostream *zstream,
					 int level, int strategy)
{
	unsigned char *hdr = zstream->gz_header;

	hdr[0] = 0x1f;
	hdr[1] = 0x8b;
	hdr[2] = Z_DEFLATED;
	hdr[8] = level == 9 ? 2 :
		(strategy >= Z_HUFFMAN_ONLY ||
		 (level != Z_DEFAULT_COMPRESSION && level < 2) ? 4 : 0);
	hdr[9] = ZLIB_OS_CODE;
	i_assert(sizeof(zstream->gz_header) == 10);
}

static struct ostream *
o_stream_create_zlib(struct ostream *output, int level, bool gz)
{
	const int strategy = Z_DEFAULT_STRATEGY;
	struct zlib_ostream *zstream;
	int ret;

	i_assert(level >= 1 && level <= 9);

	zstream = i_new(struct zlib_ostream, 1);
	zstream->ostream.sendv = o_stream_zlib_sendv;
	zstream->ostream.flush = o_stream_zlib_flush;
	zstream->ostream.iostream.close = o_stream_zlib_close;
	zstream->crc = 0;
	zstream->gz = gz;
	if (!gz)
		zstream->header_sent = TRUE;

	o_stream_zlib_init_gz_header(zstream, level, strategy);
	ret = deflateInit2(&zstream->zs, level, Z_DEFLATED, -15, 8, strategy);
	switch (ret) {
	case Z_OK:
		break;
	case Z_MEM_ERROR:
		i_fatal_status(FATAL_OUTOFMEM, "deflateInit(): Out of memory");
	case Z_VERSION_ERROR:
		i_fatal("Wrong zlib library version (broken compilation)");
	case Z_STREAM_ERROR:
		i_fatal("Invalid compression level %d", level);
	default:
		i_fatal("deflateInit() failed with %d", ret);
	}

	zstream->zs.next_out = zstream->outbuf;
	zstream->zs.avail_out = sizeof(zstream->outbuf);
	return o_stream_create(&zstream->ostream, output);
}

struct ostream *o_stream_create_gz(struct ostream *output, int level)
{
	return o_stream_create_zlib(output, level, TRUE);
}

struct ostream *o_stream_create_deflate(struct ostream *output, int level)
{
	return o_stream_create_zlib(output, level, FALSE);
}
#endif
