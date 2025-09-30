#ifndef LIB_EVENT_H
#define LIB_EVENT_H
/* event.h name is probably a bit too generic, so lets avoid using it. */

#include <sys/time.h>
#include "net.h"

/* Field name for the reason_code string list. */
#define EVENT_REASON_CODE "reason_code"

struct event;
struct event_log_params;
struct event_category_iterator;

/* Hierarchical category of events. Each event can belong to multiple
   categories. For example [ lib-storage/maildir, syscall/io ]. The categories
   are expected to live as long as they're used in events. */
struct event_category {
	struct event_category *parent;
	const char *name;

	/* non-NULL if this category has been registered

	   Do NOT dereference outside of event code in src/lib.

	   At any point in time it is safe to (1) check the pointer for
	   NULL/non-NULL to determine if this particular category instance
	   has been registered, and (2) compare two categories' internal
	   pointers to determine if they represent the same category. */
	void *internal;
};

enum event_field_value_type {
	EVENT_FIELD_VALUE_TYPE_STR,
	EVENT_FIELD_VALUE_TYPE_INTMAX,
	EVENT_FIELD_VALUE_TYPE_TIMEVAL,
	EVENT_FIELD_VALUE_TYPE_IP,
	EVENT_FIELD_VALUE_TYPE_STRLIST,
};

struct event_field {
	const char *key;
	enum event_field_value_type value_type;
	union {
		const char *str;
		intmax_t intmax;
		struct timeval timeval;
		struct {
			struct ip_addr ip;
			unsigned int ip_bits; /* set for event filters */
		};
		ARRAY_TYPE(const_string) strlist;
	} value;
};

struct event_add_field {
	const char *key;
	/* The first non-0/NULL value is used. */
	const char *value;
	intmax_t value_intmax;
	struct timeval value_timeval;
	struct ip_addr value_ip;
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
		(*add_int_nonzero)(const char *key, intmax_t num);
	struct event_passthrough *
		(*add_timeval)(const char *key, const struct timeval *tv);
	struct event_passthrough *
		(*add_ip)(const char *key, const struct ip_addr *ip);

	struct event_passthrough *
		(*inc_int)(const char *key, intmax_t num);

	struct event_passthrough *
		(*strlist_append)(const char *key, const char *value);
	struct event_passthrough *
		(*strlist_replace)(const char *key, const char *const *value,
				   unsigned int count);

	struct event_passthrough *
		(*clear_field)(const char *key);

	struct event *(*event)(void);
};

typedef const char *
event_log_prefix_callback_t(void *context);
typedef const char *
event_log_message_callback_t(void *context, enum log_type log_type,
			     const char *message);

/* Returns TRUE if the event has all the categories that the "other" event has
   (and maybe more). */
bool event_has_all_categories(struct event *event, const struct event *other);
/* Returns TRUE if the event has all the fields that the "other" event has
   (and maybe more). Only the fields in the events themselves are checked.
   Parent events' fields are not checked. */
bool event_has_all_fields(struct event *event, const struct event *other);

/* Returns the source event duplicated into a new event. Event pointers are
   dropped. */
struct event *event_dup(const struct event *source);
/* Returns a flattened version of the source event.
   Both categories and fields will be flattened.
   A new reference to the source event is returned if no flattening was
   needed. Event pointers are dropped if a new event was created. */
struct event *event_flatten(struct event *src);
/* Returns a minimized version of the source event.
   Remove parents with no fields or categories, attempt to flatten fields
   and categories to avoid sending one-off parent events.  (There is a more
   detailed description in a comment above the function implementation.)
   A new reference to the source event is returned if no simplification
   occurred. Event pointers are dropped if a new event was created. */
struct event *event_minimize(struct event *src);
/* Copy all categories from source to dest.
   Only the categories in source event itself are copied.
   Parent events' categories aren't copied. */
void event_copy_categories(struct event *to, struct event *from);
/* Copy all fields from source to dest.
   Only the fields in source event itself are copied.
   Parent events' fields aren't copied. */
void event_copy_fields(struct event *to, struct event *from);

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

/* Set the event to be the global event and push it at the top of the global
   event stack. Returns the event parameter. The event must be explicitly
   popped before it's freed.

   The global event acts as the root event for all the events while they are
   being emitted. The global events don't permanently affect the event
   hierarchy. The global events are typically used to add extra fields to all
   emitted events while some specific work is running.

   For example the global event can be "IMAP command SELECT", which can be used
   for filtering events that happen while the SELECT command is being executed.
   However, for the created struct mailbox the parent event should be the
   mail_user, not the SELECT command. (If the mailbox used SELECT command as
   the parent event, then any future event emitted via the mailbox event would
   show SELECT command as the parent, even after SELECT had already finished.)

   The global event works the same as if all the events' roots were instead
   pointing to the global event. Global events don't affect log prefixes.

   If ioloop contexts are used, the global events will automatically follow the
   contexts. Any global events pushed while running in a context are popped
   out when the context is deactivated, and pushed back when context is
   activated again.

   The created global events should use event_get_global() as their parent
   event. Only the last pushed global event is used. */
struct event *event_push_global(struct event *event);
/* Pop the current global event and set the global event to the next one at
   the top of the stack. Assert-crash if the current global event isn't the
   given event parameter. Returns the next (now activated) global event in the
   stack, or NULL if the stack is now empty. */
struct event *event_pop_global(struct event *event);
/* Returns the current global event. */
struct event *event_get_global(void);

/* Shortcut to create and push a global event and set its reason_code field. */
struct event_reason *
event_reason_begin(const char *reason_code, const char *source_filename,
		   unsigned int source_linenum);
#define event_reason_begin(reason_code) \
	event_reason_begin(reason_code, __FILE__, __LINE__)
/* Finish the reason event. It pops the global event, which means it must be
   at the top of the stack. */
void event_reason_end(struct event_reason **reason);
/* Generate a reason code as <module>:<name>. This function does some
   sanity checks and conversions to make sure the reason codes are reasonable:

   - Assert-crash if module has space, '-', ':' or uppercase characters.
   - Assert-crash if module is empty
   - Convert name to lowercase.
   - Replace all space and '-' in name with '_'.
   - Assert-crash if name has ':'
   - assert-crash if name is empty
*/
const char *event_reason_code(const char *module, const char *name);
/* Same as event_reason_code(), but concatenate name_prefix and name.
   The name_prefix must not contain spaces, '-', ':' or uppercase characters. */
const char *event_reason_code_prefix(const char *module,
				     const char *name_prefix, const char *name);

/* Set the appended log prefix string for this event. All the parent events'
   log prefixes will be concatenated together when logging. The log type
   text (e.g. "Info: ") will be inserted before appended log prefixes (but
   after replaced log prefix).

   Clears log_prefix callback.
 */
struct event *
event_set_append_log_prefix(struct event *event, const char *prefix);
/* Replace the full log prefix string for this event. The parent events' log
   prefixes won't be used. Also, any parent event's message amendment callback
   is not used.

   Clears log_prefix callback.
*/
struct event *event_replace_log_prefix(struct event *event, const char *prefix);

/* Drop count prefixes from parents when this event is used for logging. This
   does not affect the parent events. This only counts actual prefixes and not
   parents. If the count is greater than the actual number of prefixes added by
   parents, all will be dropped. */
struct event *
event_drop_parent_log_prefixes(struct event *event, unsigned int count);

/* Sets event prefix callback, sets log_prefix empty */
struct event *
event_set_log_prefix_callback(struct event *event, bool replace,
			      event_log_prefix_callback_t *callback,
			      void *context);
#define event_set_log_prefix_callback(event, replace, callback, context) \
	event_set_log_prefix_callback(event, replace, \
		(event_log_prefix_callback_t*)callback, TRUE ? context : \
		CALLBACK_TYPECHECK(callback, const char *(*)(typeof(context))))

/* Sets event message amendment callback */
struct event *
event_set_log_message_callback(struct event *event,
			       event_log_message_callback_t *callback,
			       void *context);
#define event_set_log_message_callback(event, callback, context) \
	event_set_log_message_callback(event, \
		(event_log_message_callback_t*)callback, TRUE ? context : \
		CALLBACK_TYPECHECK(callback, \
			const char *(*)(typeof(context), enum log_type, \
					const char *)))

/* Unsets the event message amendment callback. */
void event_unset_log_message_callback(struct event *event,
				      event_log_message_callback_t *callback,
				      void *context);
#define event_unset_log_message_callback(event, callback, context) \
	event_unset_log_message_callback(event, \
		(event_log_message_callback_t*)callback, context)

/* Disable calling all callbacks for the event and its children. This
   effectively allows the event to be used only for logging, but nothing else
   (no stats or other filters). */
void event_disable_callbacks(struct event *event);

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
/* Set minimum normal log level for the event. By default events with INFO
   level and higher are logged. This can be used to easily hide even the INFO
   log lines unless some verbose-setting is enabled.

   Note that this functionality is mostly independent of debug logging.
   Don't use this to enable debug log - use event_set_forced_debug() instead. */
struct event *event_set_min_log_level(struct event *event, enum log_type level);
enum log_type event_get_min_log_level(const struct event *event);

/* Add an internal pointer to an event. It can be looked up only with
   event_get_ptr(). The keys are in their own namespace and won't conflict
   with event fields. The pointers are specific to this specific event only -
   they will be dropped from any duplicated/flattened/minimized events. */
struct event *event_set_ptr(struct event *event, const char *key, void *value);
/* Return a pointer set with event_set_ptr(), or NULL if it doesn't exist.
   The pointer is looked up only from the event itself, not its parents. */
void *event_get_ptr(const struct event *event, const char *key);

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
/* Adds int value to event if it is non-zero */
struct event *
event_add_int_nonzero(struct event *event, const char *key, intmax_t num);
/* Increase the key's value. If it's not set or isn't an integer type,
   initialize the value to num. */
struct event *
event_inc_int(struct event *event, const char *key, intmax_t num);
struct event *
event_add_timeval(struct event *event, const char *key,
		  const struct timeval *tv);
struct event *
event_add_ip(struct event *event, const char *key, const struct ip_addr *ip);
/* Append new value to list. If the key is not a list, it will
   be cleared first. NULL values are ignored. Duplicate values are ignored. */
struct event *
event_strlist_append(struct event *event, const char *key, const char *value);
/* Replace value with this strlist. */
struct event *
event_strlist_replace(struct event *event, const char *key,
		      const char *const *value, unsigned int count);
/* Copy the string list from src and its parents to dest. This can be especially
   useful to copy the current global events' reason_codes to a more permanent
   (e.g. async) event that can exist after the global events are popped out. */
struct event *
event_strlist_copy_recursive(struct event *dest, const struct event *src,
			     const char *key);
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
struct event *event_get_parent(const struct event *event);
/* Returns the memory pool used by the event. */
pool_t event_get_pool(const struct event *event);
/* Get the event's creation time. */
void event_get_create_time(const struct event *event, struct timeval *tv_r);
/* Get the time when the event was last sent. Returns TRUE if time was
   returned, FALSE if event has never been sent. */
bool event_get_last_send_time(const struct event *event, struct timeval *tv_r);
/* Get the event duration field in microseconds. This is calculated from
   the event's last sent time. */
void event_get_last_duration(const struct event *event,
			     uintmax_t *duration_usecs_r);
/* Returns field for a given key, or NULL if it doesn't exist. */
struct event_field *
event_find_field_nonrecursive(const struct event *event, const char *key);
/* Returns field for a given key, or NULL if it doesn't exist. If the key
   isn't found from the event itself, find it from parent events, including
   from the global event. */
const struct event_field *
event_find_field_recursive(const struct event *event, const char *key);
/* Same as event_find_field(), but return the value converted to a string.
   If the field isn't stored as a string, the result is allocated from
   data stack. */
const char *
event_find_field_recursive_str(const struct event *event, const char *key);
/* Returns all key=value fields that the event has.
   Parent events' fields aren't returned. */
const struct event_field *
event_get_fields(const struct event *event, unsigned int *count_r);
/* Return all categories that the event has.
   Parent events' categories aren't returned. */
struct event_category *const *
event_get_categories(const struct event *event, unsigned int *count_r);

/* Iterator for scanning through all categories of the event, including the
   parents and higher ancestry of the categories directly associated with this
   event. Note that this does not include the categories of any parent event. To
   avoid useless allocation of an iterator, the event_categories_iterate_init()
   function returns NULL if no categories are associated with this event. The
   event_categories_iterate() and event_categories_iterate_deinit() functions
   safely handle this NULL iterator.
 */
struct event_category_iterator *
event_categories_iterate_init(const struct event *event);
bool event_categories_iterate(struct event_category_iterator *iter,
			      const struct event_category **cat_r);
void event_categories_iterate_deinit(struct event_category_iterator **_iter);

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

/* Enable "user_cpu_usecs" event field to event by getting current resource
   usage which will be used in consequent event_send() to calculate
   cpu time. This function can be called multiple times to update the current
   resource usage.

   The "user_cpu_usecs" field is automatically inherited by passthrough events,
   but not full events.
*/
void event_enable_user_cpu_usecs(struct event *event);

void lib_event_init(void);
void lib_event_deinit(void);

#endif
