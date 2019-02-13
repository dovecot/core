/* Copyright (c) 2013-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"

#ifdef HAVE_ZSTD

#include "buffer.h"
#include "istream-private.h"
#include "istream-zlib.h"
#include <zstd.h>

struct zstd_istream {
	struct istream_private istream;
	ZSTD_DStream* dstream;

	struct stat last_parent_statbuf;
	ZSTD_inBuffer input;
	ZSTD_outBuffer output;
	size_t next_read;
	ssize_t buffer_size;
	bool marked:1;
};

static void i_stream_zstd_init(struct zstd_istream *zstream)
{
	zstream->output.dst = malloc(ZSTD_DStreamOutSize());
	zstream->output.size = ZSTD_DStreamOutSize();
	zstream->output.pos = 0;

	zstream->input.src = malloc(ZSTD_DStreamInSize());
	zstream->input.size = ZSTD_DStreamInSize();
	zstream->input.pos = ZSTD_DStreamInSize();

	zstream->dstream = ZSTD_createDStream();
	if(zstream->dstream==NULL)
		i_fatal("zstd_stream_decore() failed to create stream");	

	zstream->next_read = ZSTD_initDStream(zstream->dstream);

	if(ZSTD_isError(zstream->next_read))
		i_fatal("zstd_stream_decode() failed to init stream with error: %s\n"
				,ZSTD_getErrorName(zstream->next_read));
}

static void 
i_stream_zstd_close(struct iostream_private *stream, bool close_parent)
{
	struct zstd_istream *zstream = (struct zstd_istream *)stream;
	
	if(zstream->dstream) {
		//ZSTD_freeDStream(zstream->dstream);
	}
	free(zstream->input.src);
	zstream->input.src = NULL;
	free(zstream->output.dst);
	zstream->output.dst = NULL;
	if (close_parent)
		i_stream_close(zstream->istream.parent);
}
static void i_stream_zstd_decompress(struct zstd_istream *zstream) {
	struct istream_private *stream = (struct istream_private *)zstream;
	const unsigned char *data;
	size_t size;
	if(zstream->next_read || !stream->istream.eof ) {
		//move everything to back of buffer
		memmove(zstream->input.src,
				zstream->input.src+zstream->input.pos,
				zstream->input.size-zstream->input.pos);
		// we have zstream->input.pos free bytes
		while(zstream->input.pos) {
			//lets fill input buffer
			if(i_stream_read_more(stream->parent, &data, &size) < 0 ) {	
				if(stream->parent->stream_errno != 0) {
					stream->istream.stream_errno = stream->parent->stream_errno;
				} else {	
					i_assert(stream->parent->eof);
					zstream->input.size -= zstream->input.pos;
					zstream->input.pos = 0;
					continue;
					//zstd_stream_end(zstream);
					stream->istream.eof = TRUE;
				}
				return -1;
			}
			if(size > zstream->input.pos) {
				size = zstream->input.pos;
			}
			memcpy(zstream->input.src+zstream->input.size-zstream->input.pos,
					data,size);
			zstream->input.pos -= size;
			i_stream_skip(stream->parent,size);
		}
	}


//	printf("%d:%d->%d:%d\n",zstream->input.size,zstream->input.pos,zstream->output.size,zstream->output.pos);

	auto to_read = ZSTD_decompressStream(zstream->dstream,&zstream->output,
			&zstream->input);
	if(ZSTD_isError(to_read)) {
		if(to_read == -70) {
			//well we need more space i guess
		}
		i_fatal("zstd_stream_read() failed to do stuff(%d): %s",to_read,
			ZSTD_getErrorName(to_read));
	}	
//	printf("%d:%d->%d:%d\n",zstream->input.size,zstream->input.pos,	zstream->output.size,zstream->output.pos);	
		
	zstream->next_read = to_read;
}

static ssize_t i_stream_zstd_read(struct istream_private *stream) {
	struct zstd_istream *zstream = (struct zstd_istream *)stream;
	ssize_t buffer_size = 1;


	if(zstream->output.pos == 0) {	
		i_stream_zstd_decompress(zstream);
		if(zstream->output.pos == 0) {
			stream->istream.eof = TRUE;
			return -1;
		}
	}

	if(!zstream->marked) {
		if(!i_stream_try_alloc(stream,zstream->output.pos,&buffer_size)){
			i_fatal("failed to allocate more space");
			return -2;
		}
	} else {
		if(!i_stream_try_alloc_avoid_compress(stream,
					zstream->output.pos,&buffer_size)) {
			i_fatal("failed to alloc more space without compression");
			return -2;
		}
	}
	// check if we need more data?
	if(zstream->output.pos < buffer_size) {
		buffer_size = zstream->output.pos;
	}
	//copy that mem
	memcpy(stream->w_buffer+stream->pos,zstream->output.dst
			,buffer_size);
	stream->pos += buffer_size;

	zstream->output.pos -= buffer_size;
	memmove(zstream->output.dst,zstream->output.dst+buffer_size
			,zstream->output.pos);

	return buffer_size;
}
static void i_stream_zstd_reset(struct zstd_istream *zstream)
{
	struct istream_private *stream = &zstream->istream;
	i_stream_seek(stream->parent,stream->parent_start_offset);

	stream->parent_expected_offset = stream->parent_start_offset;
	stream->skip = stream->pos = 0;
	stream->istream.v_offset = 0;


	i_stream_zstd_init(zstream);
}
static void 
i_stream_zstd_seek(struct istream_private *stream,uoff_t v_offset, bool mark)
{
	struct zstd_istream *zstream = (struct zstd_istream *)stream;

	if(i_stream_nonseekable_try_seek(stream,v_offset))
		return 0;

	i_stream_zstd_reset(zstream);
	if(!i_stream_nonseekable_try_seek(stream,v_offset))
		i_unreached();

	if(mark)
		zstream->marked = TRUE;
}

static void i_stream_zstd_sync(struct istream_private *stream){
	struct zstd_istream *zstream = (struct zstd_istream *)stream;
	const struct stat *st;

	if (i_stream_stat(stream->parent, FALSE, &st) < 0) {
		if(memcmp(&zstream->last_parent_statbuf,
					st, sizeof(*st)) == 0) {
			return;
		}
		zstream->last_parent_statbuf = *st;
	}
	i_stream_zstd_reset(zstream);
}

struct istream *i_stream_create_zstd(struct istream *input, bool log_errors)
{
	struct zstd_istream *zstream;
	zstream = i_new(struct zstd_istream, 1);

	i_stream_zstd_init(zstream);

	zstream->istream.iostream.close = i_stream_zstd_close;
	zstream->istream.max_buffer_size = input->real_stream->max_buffer_size;
	zstream->istream.read = i_stream_zstd_read;
	zstream->istream.seek = i_stream_zstd_seek;
	zstream->istream.sync = i_stream_zstd_sync;


	//TODO: why
	zstream->istream.istream.readable_fd = FALSE;

	zstream->istream.istream.blocking = input->blocking;
	zstream->istream.istream.seekable = input->seekable;

	return i_stream_create(&zstream->istream, input,
			i_stream_get_fd(input),0);
}
#endif
