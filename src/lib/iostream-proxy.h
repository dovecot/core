/* Copyright (c) 2002-2017 Dovecot authors, see the included COPYING file
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
	IOSTREAM_PROXY_SIDE_LEFT,
	IOSTREAM_PROXY_SIDE_RIGHT
};

typedef void iostream_proxy_callback_t(enum iostream_proxy_side side,
				       bool success,
				       void *context);

struct iostream_proxy *
iostream_proxy_create(struct istream *left_input, struct ostream *left_output,
		      struct istream *right_input, struct ostream *right_output);

struct istream *iostream_proxy_get_istream(struct iostream_proxy *proxy, enum iostream_proxy_side);
struct ostream *iostream_proxy_get_ostream(struct iostream_proxy *proxy, enum iostream_proxy_side);

void iostream_proxy_start(struct iostream_proxy *proxy);
void iostream_proxy_stop(struct iostream_proxy *proxy);

void iostream_proxy_set_completion_callback(struct iostream_proxy *proxy,
				       iostream_proxy_callback_t *callback, void *context);
#define iostream_proxy_set_completion_callback(proxy, callback, context) \
	iostream_proxy_set_completion_callback(proxy, (iostream_proxy_callback_t *)callback, context + \
		CALLBACK_TYPECHECK(callback, void (*)(enum iostream_proxy_side side, bool, typeof(context))))

void iostream_proxy_ref(struct iostream_proxy *proxy);
void iostream_proxy_unref(struct iostream_proxy **proxy_r);

void iostream_proxy_switch_ioloop(struct iostream_proxy *proxy);

#endif
