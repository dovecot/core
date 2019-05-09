/* Copyright (c) 2002-2018 Dovecot authors, see the included COPYING file
 */
#ifndef IOSTREAM_PROXY_H
#define IOSTREAM_PROXY_H 1

/**

iostream-proxy
=============

This construct will proxy data between two pairs of
istream and ostream. Data is proxied from left to right
and right to left using iostream-pump.

The proxy requires you to provide completion callback. The
completion callback is called with success parameter to
indicate whether it ended with error.

The istreams and ostreams are reffed on creation and unreffed
on unref.

**/

struct istream;
struct ostream;
struct iostream_proxy;

enum iostream_proxy_side {
	/* Input is coming from left side's istream and is proxied to
	   right side's ostream. */
	IOSTREAM_PROXY_SIDE_LEFT,
	/* Input is coming from right side's istream and is proxied to
	   left side's ostream. */
	IOSTREAM_PROXY_SIDE_RIGHT
};

enum iostream_proxy_status {
	/* proxy succeeded - EOF received from istream and all output was
	   written successfully to ostream. */
	IOSTREAM_PROXY_STATUS_INPUT_EOF,
	/* proxy failed - istream returned an error */
	IOSTREAM_PROXY_STATUS_INPUT_ERROR,
	/* proxy failed - other side's ostream returned an error */
	IOSTREAM_PROXY_STATUS_OTHER_SIDE_OUTPUT_ERROR,
};

/* The callback maybe be called once or twice. Usually the first call should
   destroy the proxy, but it's possible for it to just wait for the other
   direction of the proxy to finish as well and call the callback.

   Note that the sides mean which side is the reader side. If the failure is in
   ostream, it's the other side's ostream that failed. So for example if
   side=left, the write failed to the right side's ostream.

   The callback is called when the proxy succeeds or fails due to
   iostreams. (It's not called if proxy is destroyed.) */
typedef void iostream_proxy_callback_t(enum iostream_proxy_side side,
				       enum iostream_proxy_status status,
				       void *context);

struct iostream_proxy *
iostream_proxy_create(struct istream *left_input, struct ostream *left_output,
		      struct istream *right_input, struct ostream *right_output);

struct istream *iostream_proxy_get_istream(struct iostream_proxy *proxy, enum iostream_proxy_side);
struct ostream *iostream_proxy_get_ostream(struct iostream_proxy *proxy, enum iostream_proxy_side);

void iostream_proxy_start(struct iostream_proxy *proxy);
void iostream_proxy_stop(struct iostream_proxy *proxy);

/* See iostream_pump_is_waiting_output() */
bool iostream_proxy_is_waiting_output(struct iostream_proxy *proxy,
				      enum iostream_proxy_side side);

void iostream_proxy_set_completion_callback(struct iostream_proxy *proxy,
				       iostream_proxy_callback_t *callback, void *context);
#define iostream_proxy_set_completion_callback(proxy, callback, context) \
	iostream_proxy_set_completion_callback(proxy, (iostream_proxy_callback_t *)callback, context - \
		CALLBACK_TYPECHECK(callback, void (*)(enum iostream_proxy_side side, enum iostream_proxy_status, typeof(context))))

void iostream_proxy_ref(struct iostream_proxy *proxy);
void iostream_proxy_unref(struct iostream_proxy **proxy_r);

void iostream_proxy_switch_ioloop(struct iostream_proxy *proxy);

#endif
