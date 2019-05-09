#ifndef LIB_EVENT_H
#define LIB_EVENT_H
/* event.h name is probably a bit too generic, so lets avoid using it. */

#include <sys/time.h>

struct event;

/* Hierarchical category of events. Each event can belong to multiple
   categories. For example [ lib-storage/maildir, syscall/io ]. The categories
   are expected to live as long as they're used in events. */
struct event_category {
	struct event_category *parent;
	const char *name;

	/* TRUE after an event with this category is sent the first time */
	bool registered;
};

enum event_field_value_type {
	EVENT_FIELD_VALUE_TYPE_STR,
	EVENT_FIELD_VALUE_TYPE_INTMAX,
	EVENT_FIELD_VALUE_TYPE_TIMEVAL,
};

struct event_field {
	const char *key;
	enum event_field_value_type value_type;
	struct {
		const char *str;
		intmax_t intmax;
		struct timeval timeval;
	} value;
};

struct event_add_field {
	const char *key;
	/* The first non-0/NULL value is used. */
	const char *value;
	intmax_t value_intmax;
	struct timeval value_timeval;
};

struct event_passthrough {
	/* wrappers to event_set_*() and event_add_*() for passthrough events,
	   so these can be chained like:
	   event_create_passthrough(parent)->name("name")->...->event() */
	struct event_passthrough *
		(*append_log_prefix)(const char *prefix);
	struct event_passthrough *
		(*replace_log_prefix)(const char *prefix);
	struct event_passthrough *
		(*set_name)(const char *name);
	struct event_passthrough *
		(*set_source)(const char *filename,
			      unsigned int linenum, bool literal_fname);
	struct event_passthrough *
		(*set_always_log_source)(void);

	struct event_passthrough *
		(*add_categories)(struct event_category *const *categories);
	struct event_passthrough *
		(*add_category)(struct event_category *category);
	struct event_passthrough *
		(*add_fields)(const struct event_add_field *fields);

	struct event_passthrough *
		(*add_str)(const char *key, const char *value);
	struct event_passthrough *
		(*add_int)(const char *key, intmax_t num);
	struct event_passthrough *
		(*add_timeval)(const char *key, const struct timeval *tv);

	struct event_passthrough *
		(*inc_int)(const char *key, intmax_t num);

	struct event *(*event)(void);
};

typedef const char *event_log_prefix_callback_t(void *context);

/* Returns TRUE if the event has all the categories that the "other" event has (and maybe more). */
bool event_has_all_categories(struct event *event, const struct event *other);
/* Returns TRUE if the event has all the fields that the "other" event has (and maybe more).
   Only the fields in the events themselves are checked. Parent events' fields are not checked. */
bool event_has_all_fields(struct event *event, const struct event *other);

/* Returns the source event duplicated into a new event. */
struct event *event_dup(const struct event *source);
/* Copy all categories and fields from source to dest.
   Only the fields and categories in source event itself are copied.
   Parent events' fields and categories aren't copied. */
void event_copy_categories_fields(struct event *dest, struct event *source);

/* Create a new empty event under the parent event, or NULL for root event. */
struct event *event_create(struct event *parent, const char *source_filename,
			   unsigned int source_linenum);
#define event_create(parent) \
	event_create((parent), __FILE__, __LINE__)
/* This is a temporary "passthrough" event. Its main purpose is to make it
   easier to create temporary events as part of the event parameter in
   e_error(), e_warning(), e_info() or e_debug(). These passthrough events are
   automatically freed when the e_*() call is finished. Because this makes the
   freeing less obvious, it should be avoided outside e_*()'s event parameter.

   The passthrough events also change the API to be more convenient towards
   being used in a parameter. Instead of having to use e.g.
   event_add_str(event_set_name(event_create(parent), "name"), "key", "value")
   the event_passthrough API can be a bit more readable as:
   event_create_passthrough(parent)->set_name("name")->
   add_str("key", "value")->event(). The passthrough event is converted to
   a normal event at the end with the event() call. Note that this API works
   by modifying the last created passthrough event, so it's not possible to
   have multiple passthrough events created in parallel. */
struct event_passthrough *
event_create_passthrough(struct event *parent, const char *source_filename,
			 unsigned int source_linenum);
#define event_create_passthrough(parent) \
	event_create_passthrough((parent), __FILE__, __LINE__)

/* Reference the event. Returns the event parameter. */
struct event *event_ref(struct event *event);
/* Unreference the event. If the reference count drops to 0, the event is
   freed. The current global event's refcount must not drop to 0. */
void event_unref(struct event **event);

/* Set the event to be the global default event used by i_error(), etc.
   Returns the event parameter. The event must be explicitly popped before
   it's freed.

   The global event stack is also an alternative nonpermanent hierarchy for
   events. For example the global event can be "IMAP command SELECT", which
   can be used for filtering events that happen while the SELECT command is
   being executed. However, for the created struct mailbox the parent event
   should be the mail_user, not the SELECT command. Otherwise everything else
   that happens afterwards to the selected mailbox would also count towards
   SELECT. This means that events shouldn't be using the current global event
   as their parent event. */
struct event *event_push_global(struct event *event);
/* Pop the global event. Assert-crash if the current global event isn't the
   given event parameter. Returns the new global event. */
struct event *event_pop_global(struct event *event);
/* Returns the current global event. */
struct event *event_get_global(void);

/* Set the appended log prefix string for this event. All the parent events'
   log prefixes will be concatenated together when logging. The log type
   text (e.g. "Info: ") will be inserted before appended log prefixes (but
   after replaced log prefix).

   Clears log_prefix callback.
 */
struct event *
event_set_append_log_prefix(struct event *event, const char *prefix);
/* Replace the full log prefix string for this event. The parent events' log
   prefixes won't be used.

   Clears log_prefix callback.
*/
struct event *event_replace_log_prefix(struct event *event, const char *prefix);


/* Sets event prefix callback, sets log_prefix empty */
struct event *event_set_log_prefix_callback(struct event *event,
					    bool replace,
					    event_log_prefix_callback_t *callback,
					    void *context);
#define event_set_log_prefix_callback(event, replace, callback, context) \
	event_set_log_prefix_callback(event, replace, (event_log_prefix_callback_t*)callback, \
		context - CALLBACK_TYPECHECK(callback, const char *(*)(typeof(context))))

/* Set the event's name. The name is specific to a single sending of an event,
   and it'll be automatically cleared once the event is sent. This should
   typically be used only in a parameter to e_debug(), etc. */
struct event *
event_set_name(struct event *event, const char *name);
/* Set the source filename:linenum to the event. If literal_fname==TRUE,
   it's assumed that __FILE__ has been used and the pointer is stored directly,
   otherwise the filename is strdup()ed. */
struct event *
event_set_source(struct event *event, const char *filename,
		 unsigned int linenum, bool literal_fname);
/* Always include the source path:line in the log replies. This is
   especially useful when logging about unexpected syscall failures, because
   it allow quickly finding which of the otherwise identical syscalls in the
   code generated the error. */
struct event *event_set_always_log_source(struct event *event);
/* Set minimum log level for the event */
struct event *event_set_min_log_level(struct event *event, enum log_type level);
enum log_type event_get_min_log_level(const struct event *event);

/* Add NULL-terminated list of categories to the event. The categories pointer
   doesn't need to stay valid afterwards, but the event_category structs
   themselves must be. Returns the event parameter. */
struct event *
event_add_categories(struct event *event,
		     struct event_category *const *categories);
/* Add a single category to the event. */
struct event *
event_add_category(struct event *event, struct event_category *category);

/* Add key=value field to the event. If a key already exists, it's replaced.
   Child events automatically inherit key=values from their parents at the
   time the event is sent. So changing a key in parent will change the values
   in the child events as well, unless the key has been overwritten in the
   child event. Setting the value to "" is the same as event_field_clear().
   Returns the event parameter. */
struct event *
event_add_str(struct event *event, const char *key, const char *value);
struct event *
event_add_int(struct event *event, const char *key, intmax_t num);
/* Increase the key's value. If it's not set or isn't an integer type,
   initialize the value to num. */
struct event *
event_inc_int(struct event *event, const char *key, intmax_t num);
struct event *
event_add_timeval(struct event *event, const char *key,
		  const struct timeval *tv);
/* Same as event_add_str/int(), but do it via event_field struct. The fields
   terminates with key=NULL. Returns the event parameter. */
struct event *
event_add_fields(struct event *event, const struct event_add_field *fields);
/* Mark a field as nonexistent. If a parent event has the field set, this
   allows removing it from the child event. Using an event filter with e.g.
   "key=*" won't match this field anymore, although it's still visible in
   event_find_field*() and event_get_fields(). This is the same as using
   event_add_str() with value="". */
void event_field_clear(struct event *event, const char *key);

/* Returns the parent event, or NULL if it doesn't exist. */
struct event *event_get_parent(struct event *event);
/* Get the event's creation time. */
void event_get_create_time(struct event *event, struct timeval *tv_r);
/* Get the time when the event was last sent. Returns TRUE if time was
   returned, FALSE if event has never been sent. */
bool event_get_last_send_time(struct event *event, struct timeval *tv_r);
/* Get the event duration field, calculated after event has been sent. */
void event_get_last_duration(struct event *event, intmax_t *duration_msec_r);
/* Returns field for a given key, or NULL if it doesn't exist. If the key
   isn't found from the event itself, find it from parent events. */
const struct event_field *
event_find_field(struct event *event, const char *key);
/* Returns the given key's value as string, or NULL if it doesn't exist.
   If the field isn't stored as a string, the result is allocated from
   data stack. */
const char *
event_find_field_str(struct event *event, const char *key);
/* Returns all key=value fields that the event has.
   Parent events' fields aren't returned. */
const struct event_field *
event_get_fields(struct event *event, unsigned int *count_r);
/* Return all categories that the event has.
   Parent events' categories aren't returned. */
struct event_category *const *
event_get_categories(struct event *event, unsigned int *count_r);

/* Export the event into a tabescaped string, so its fields are separated
   with TABs and there are no NUL, CR or LF characters. */
void event_export(const struct event *event, string_t *dest);
/* Import event. The string is expected to be generated by event_export().
   All the used categories must already be registered.
   Returns TRUE on success, FALSE on invalid string. */
bool event_import(struct event *event, const char *str, const char **error_r);
/* Same as event_import(), but string is already split into an array
   of strings via *_strsplit_tabescaped(). */
bool event_import_unescaped(struct event *event, const char *const *args,
			    const char **error_r);

/* The event wasn't sent after all - free everything related to it.
   Most importantly this frees any passthrough events. Typically this shouldn't
   need to be called. */
void event_send_abort(struct event *event);

/* Explicitly register an event category. It must not be in use by any events
   at this point. This is normally necessary only when unloading an plugin
   that has registered an event category. */
void event_category_unregister(struct event_category *category);

void lib_event_init(void);
void lib_event_deinit(void);

#endif
