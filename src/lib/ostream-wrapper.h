#ifndef OSTREAM_WRAPPER_H
#define OSTREAM_WRAPPER_H

#include "ostream-private.h"

/* The wrapper output stream allows turning any form* of activity involving data
   output into a standard Dovecot output stream. The wrapper output stream can
   operate both in blocking and non-blocking mode. When the wrapped activity is
   non-blocking, a blocking wrapper output stream will implicitly run its own
   ioloop.

   It is possible to have the wrapper output stream object available even before
   the data can be written anywhere, even before any form of output object (a
   connection) exists. In that case, any data written to the wrapper stream is
   buffered until the buffer is full. Once that happens, the stream will block
   or refuse writes until the underlying output becomes available.

   The wrapper output stream is not meant to be used directly. Instead, it is
   to be used as part of the implementation of an application-specific output
   stream. The wrapper output stream serves as the means to prevent code
   duplication between similar output stream implementations. It defines several
   methods that need to be implemented by the application-specific output
   stream.

   * Currently, the wrapper stream still expects an output stream object when
     data is to be written somewhere, but that should be easily circumvented
     once such behavior is needed (FIXME).
 */

struct wrapper_ostream {
	struct ostream_private ostream;
	struct event *event;

	/* Called when the implementation should start making the parent output
	   stream available, e.g. connect to the server. This happens when data
	   was written to the wrapper ostream (when it is corked this only
	   happens when the wrapper ostream buffer is full or the wrapper
	   ostream is finished). */
	void (*output_start)(struct wrapper_ostream *wostream);
	/* Returns TRUE when the output is ready for data. */
	bool (*output_ready)(struct wrapper_ostream *wostream);
	/* Called when an error occurred while writing to the output stream. */
	void (*output_error)(struct wrapper_ostream *wostream);
	/* Called when the wrapper ostream was finished using o_stream_finish()
	   and the wrapper ostream buffer is empty. Also, the parent output
	   was flushed successfully. */
	int (*output_finish)(struct wrapper_ostream *wostream);
	/* Called when the wrapper ostream does not need write to parent output
	   stream. This is will e.g. drop the parent output's flush callback or
	   equivalent notification mechanism. */
	void (*output_halt)(struct wrapper_ostream *wostream);
	/* Called when the wrapper ostream has data available for the parent
	   output and wants wrapper_ostream_continue() to be called when the
	   parent stream is writeable. */
	void (*output_resume)(struct wrapper_ostream *wostream);
	/* Update the timeouts. The sender_blocking parameter indicates which
	   side of the data transfer is blocking, so whether a timeout needs to
	   be set for limiting the time other side is not doing anything. */
	void (*output_update_timeouts)(struct wrapper_ostream *wostream,
				       bool sender_blocking);

	/* Called before and after running ioloop for performing blocking I/O
	   wait. Use these vfuncs to switch to and from the temporary ioloop. */
	struct ioloop *(*wait_begin)(struct wrapper_ostream *wostream,
				     struct ioloop *ioloop);
	void (*wait_end)(struct wrapper_ostream *wostream,
			 struct ioloop *prev_ioloop);

	/* Called before and after running the flush callback for the ostream.
	  */
	void (*callback_pre)(struct wrapper_ostream *wostream);
	void (*callback_post)(struct wrapper_ostream *wostream);

	/* Called when the ostream is switched to a different ioloop. */
	void (*switch_ioloop_to)(struct wrapper_ostream *wostream,
				 struct ioloop *ioloop);

	/* Called when the wrapper ostream is forcibly closed using
	   o_stream_close() (or indirectly through e.g. o_stream_destroy()). */
	void (*close)(struct wrapper_ostream *wostream);
	/* Called when the ostream is destroyed. */
	void (*destroy)(struct wrapper_ostream *wostream);

	buffer_t *buffer; // FIXME: use a ringbuffer instead (file_ostream)

	/* The (parent) output stream. */
	struct ostream *output;

	/* The ioloop used while flushing/sending output for when the wrapper
	   ostream is blocking. */
	struct ioloop *flush_ioloop;

	/* Error set using wrapper_ostream_return_error(). This is returned to
	   the application once it continues using the wrapper ostream. */
	char *pending_error;
	int pending_errno;

	/* Timeout for delayed execution of wrapper_ostream_continue(). */
	struct timeout *to_event;

	/* Output was started (output_start() vfunc was called). */
	bool output_started:1;
	/* Output was finished (output_finish() vfunc was called). */
	bool output_finished:1;
	/* Output was was closed somehow. This means that the output is no
	   longer available. This is not the same as the ostream close flag. */
	bool output_closed:1;
	/* Output was closed directly or indirectly by the application action.
	 */
	bool output_closed_api:1;

	bool flush_pending:1;
	bool flush_waiting:1;
	bool flushing:1;
	bool continuing:1;
	bool returned_error:1;
};

/* Create the wrapper output stream. This function calls o_stream_create()
   internally. The initial maximum buffer size is set to max_buffer_size. When
   blocking is TRUE, a blocking output stream will be created. The provided
   event is used internally for debug logging. */
struct ostream *
wrapper_ostream_create(struct wrapper_ostream *wostream,
		       size_t max_buffer_size, bool blocking,
		       struct event *event) ATTR_NULL(4);

/* Continue sending output. */
void wrapper_ostream_continue(struct wrapper_ostream *wostream);
/* Trigger an (asynchronous) flush on the output stream. */
void wrapper_ostream_trigger_flush(struct wrapper_ostream *wostream);

/* This function returns the size of the data buffered in the wrapper stream,
   but only when the output stream is finished using o_stream_finish(). When the
   output stream is finished, the data is complete and this function returns
   TRUE and size_r is set to the size. If it is not complete, this function
   returns FALSE and size_r is not assigned. This function is meant to be called
   just before sending the first block of data internally for deciding between
   sending the data using a chunked transfer encoding or, when it is already
   complete, as a single blob with known size. E.g., for HTTP this is the choice
   between sending the message using the Transfer-Encoding: chunked header or
   the Content-Length header. */
bool wrapper_ostream_get_buffered_size(struct wrapper_ostream *wostream,
				       uoff_t *size_r);

/* Call this when the underlying output stream first becomes available. */
void wrapper_ostream_output_available(struct wrapper_ostream *wostream,
				      struct ostream *output);
/* Call this to notify the wrapper that the underlying output is destroyed and
   no more data can be written ever. */
void wrapper_ostream_output_destroyed(struct wrapper_ostream *wostream);

/* Call this to notify the wrapper that an error has occurred. It will be
   returned as such for the next stream write/flush and subsequent
   o_stream_get_error(). */
void wrapper_ostream_set_error(struct wrapper_ostream *wostream,
			       int stream_errno, const char *stream_error);
/* Notify the application immediately about any error condition set earlier
   using wrapper_ostream_set_error() by calling the ostream flush callback
   right now.
 */
void wrapper_ostream_notify_error(struct wrapper_ostream *wostream);

#endif
