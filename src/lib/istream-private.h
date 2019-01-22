#ifndef ISTREAM_PRIVATE_H
#define ISTREAM_PRIVATE_H

#include "istream.h"
#include "iostream-private.h"

#define I_STREAM_MIN_SIZE IO_BLOCK_SIZE

struct io;

struct istream_private {
/* inheritance: */
	struct iostream_private iostream;

/* methods: */
	ssize_t (*read)(struct istream_private *stream);
	void (*seek)(struct istream_private *stream,
		     uoff_t v_offset, bool mark);
	void (*sync)(struct istream_private *stream);
	int (*stat)(struct istream_private *stream, bool exact);
	int (*get_size)(struct istream_private *stream, bool exact, uoff_t *size_r);
	void (*switch_ioloop_to)(struct istream_private *stream,
				 struct ioloop *ioloop);
	struct istream_snapshot *
		(*snapshot)(struct istream_private *stream,
			    struct istream_snapshot *prev_snapshot);

/* data: */
	struct istream istream;

	int fd;
	uoff_t start_offset;
	struct stat statbuf;
	/* added by io_add_istream() -> i_stream_set_io() */
	struct io *io;

	const unsigned char *buffer;
	unsigned char *w_buffer; /* may be NULL */

	size_t buffer_size, max_buffer_size, init_buffer_size;
	size_t skip, pos, try_alloc_limit;
	/* If seeking backwards within the buffer, the next read() will
	   return again pos..high_pos */
	size_t high_pos;

	struct istream *parent; /* for filter streams */
	uoff_t parent_start_offset;
	/* Initially (uoff_t)-1. Otherwise it's the exact known stream size,
	   which can be used by stat() / get_size(). */
	uoff_t cached_stream_size;

	/* parent stream's expected offset is kept here. i_stream_read()
	   always seeks parent stream to here before calling read(). */
	uoff_t parent_expected_offset;

	struct memarea *memarea;
	struct istream_snapshot *prev_snapshot;
	/* increased every time the stream is changed (e.g. seek, read).
	   this way streams can check if their parent streams have been
	   accessed behind them. */
	unsigned int access_counter;
	/* Timestamp when read() last returned >0 */
	struct timeval last_read_timeval;

	string_t *line_str; /* for i_stream_next_line() if w_buffer == NULL */
	bool line_crlf:1;
	bool return_nolf_line:1;
	bool stream_size_passthrough:1; /* stream is parent's size */
	bool nonpersistent_buffers:1;
	bool io_pending:1;
};

struct istream_snapshot {
	struct istream_snapshot *prev_snapshot;
	struct memarea *old_memarea;
};

enum istream_create_flag {
	/* The stream guarantees that the buffer pointer stays valid when it
	   returns <= 0. */
	ISTREAM_CREATE_FLAG_NOOP_SNAPSHOT	= 0x01,
};

struct istream * ATTR_NOWARN_UNUSED_RESULT
i_stream_create(struct istream_private *stream, struct istream *parent, int fd,
		enum istream_create_flag flags) ATTR_NULL(2);
/* Initialize parent lazily after i_stream_create() has already been called. */
void i_stream_init_parent(struct istream_private *_stream,
			  struct istream *parent);

void i_stream_compress(struct istream_private *stream);
void i_stream_grow_buffer(struct istream_private *stream, size_t bytes);
bool ATTR_NOWARN_UNUSED_RESULT
i_stream_try_alloc(struct istream_private *stream,
		   size_t wanted_size, size_t *size_r);
/* Like i_stream_try_alloc(), but compress only if it's the only way to get
   more space. This can be useful when stream is marked with
   i_stream_seek_mark() */
bool ATTR_NOWARN_UNUSED_RESULT
i_stream_try_alloc_avoid_compress(struct istream_private *stream,
				  size_t wanted_size, size_t *size_r);
void *i_stream_alloc(struct istream_private *stream, size_t size);
/* Free memory allocated by i_stream_*alloc() */
void i_stream_free_buffer(struct istream_private *stream);
ssize_t i_stream_read_copy_from_parent(struct istream *istream);
void i_stream_default_seek_nonseekable(struct istream_private *stream,
				       uoff_t v_offset, bool mark);
/* Returns FALSE if seeking must be done by starting from the beginning.
   The caller is then expected to reset the stream and call this function
   again, which should work then. If TRUE is returned, the seek was either
   successfully done or stream_errno is set. */
bool i_stream_nonseekable_try_seek(struct istream_private *stream,
				   uoff_t v_offset);

/* Default snapshot handling: use memarea if it exists, otherwise snapshot
   parent stream. */
struct istream_snapshot *
i_stream_default_snapshot(struct istream_private *stream,
			  struct istream_snapshot *prev_snapshot);
void i_stream_snapshot_free(struct istream_snapshot **snapshot);

struct istream *i_stream_get_root_io(struct istream *stream);
void i_stream_set_io(struct istream *stream, struct io *io);
void i_stream_unset_io(struct istream *stream, struct io *io);

/* Filter istreams should be calling this instead of i_stream_read() to avoid
   unnecessarily referencing memareas. After this call any pointers to the
   parent istream's content must be considered as potentially invalid and have
   to be updated, even if the return value is <=0. */
ssize_t i_stream_read_memarea(struct istream *stream);
int i_stream_read_more_memarea(struct istream *stream,
			       const unsigned char **data_r, size_t *size_r);

#endif
