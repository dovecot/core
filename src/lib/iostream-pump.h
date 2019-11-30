#ifndef IOSTREAM_PUMP_H
#define IOSTREAM_PUMP_H

/* iostream-pump
   =============

   This construct pumps data from istream to ostream asynchronously.

   The pump requires you to provide completion callback. The completion
   callback is called with success parameter to indicate whether it ended
   with error.
   
   The istream and ostream are reffed on creation and unreffed
   on unref.
 */

struct istream;
struct ostream;
struct iostream_pump;

enum iostream_pump_status {
	/* pump succeeded - EOF received from istream and all output was
	   written successfully to ostream. */
	IOSTREAM_PUMP_STATUS_INPUT_EOF,
	/* pump failed - istream returned an error */
	IOSTREAM_PUMP_STATUS_INPUT_ERROR,
	/* pump failed - ostream returned an error */
	IOSTREAM_PUMP_STATUS_OUTPUT_ERROR,
};

/* The callback is called once when the pump succeeds or fails due to
   iostreams. (It's not called if pump is destroyed.) */
typedef void iostream_pump_callback_t(enum iostream_pump_status status,
				      void *context);

struct iostream_pump *
iostream_pump_create(struct istream *input, struct ostream *output);

struct istream *iostream_pump_get_input(struct iostream_pump *pump);
struct ostream *iostream_pump_get_output(struct iostream_pump *pump);

void iostream_pump_start(struct iostream_pump *pump);
void iostream_pump_stop(struct iostream_pump *pump);

void iostream_pump_ref(struct iostream_pump *pump);
void iostream_pump_unref(struct iostream_pump **_pump);
void iostream_pump_destroy(struct iostream_pump **_pump);

void iostream_pump_set_completion_callback(struct iostream_pump *pump,
					   iostream_pump_callback_t *callback,
					   void *context);
#define iostream_pump_set_completion_callback(pump, callback, context) \
	iostream_pump_set_completion_callback(pump, \
		(iostream_pump_callback_t *)callback, TRUE ? context : \
		CALLBACK_TYPECHECK(callback, \
			void (*)(enum iostream_pump_status, typeof(context))))

/* Returns TRUE if the pump is currently only writing to the ostream. The input
   listener has been removed either because the ostream buffer is full or
   because the istream already returned EOF. This function can also be called
   from the completion callback in error conditions. */
bool iostream_pump_is_waiting_output(struct iostream_pump *pump);

void iostream_pump_switch_ioloop(struct iostream_pump *pump);

#endif
