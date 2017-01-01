/* Copyright (c) 2002-2017 Dovecot authors, see the included COPYING file
 */
#ifndef IOSTREAM_PUMP_H
#define IOSTREAM_PUMP_H 1

/**

iostream-pump
=============

This construct pumps data from istream to ostream asynchronously.

The pump requires you to provide completion callback. The
completion callback is called with success parameter to
indicate whether it ended with error.

The istream and ostream are reffed on creation and unreffed
on unref.

**/

struct istream;
struct ostream;
struct iostream_pump;

typedef void iostream_pump_callback_t(bool success, void *context);

struct iostream_pump *
iostream_pump_create(struct istream *input, struct ostream *output);

struct istream *iostream_pump_get_input(struct iostream_pump *pump);
struct ostream *iostream_pump_get_output(struct iostream_pump *pump);

void iostream_pump_start(struct iostream_pump *pump);
void iostream_pump_stop(struct iostream_pump *pump);

void iostream_pump_ref(struct iostream_pump *pump);
void iostream_pump_unref(struct iostream_pump **pump_r);

void iostream_pump_set_completion_callback(struct iostream_pump *pump,
					   iostream_pump_callback_t *callback, void *context);
#define iostream_pump_set_completion_callback(pump, callback, context) \
	iostream_pump_set_completion_callback(pump, (iostream_pump_callback_t *)callback, context + \
		CALLBACK_TYPECHECK(callback, void (*)(bool, typeof(context))))

void iostream_pump_switch_ioloop(struct iostream_pump *pump);

#endif
