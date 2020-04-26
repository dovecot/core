#ifndef LIB_EVENT_PRIVATE_H
#define LIB_EVENT_PRIVATE_H

struct event_pointer {
	const char *key;
	void *value;
};

struct event {
	struct event_passthrough event_passthrough;
	/* linked list of all events, newest first */
	struct event *prev, *next;

	int refcount;
	pool_t pool;
	struct event *parent;
	uint64_t id;

	/* Avoid sending the event to stats over and over.  The 'change_id'
	   increments every time something about this event changes.  If
	   'sent_to_stats_id' matches 'change_id', we skip sending this
	   event out.  If it doesn't match, we send it and set
	   'sent_to_stats_id' to 'change_id'. sent_to_stats_id=0 is reserved
	   for "event hasn't been sent". 'change_id' can never be 0. */
	uint32_t change_id;
	uint32_t sent_to_stats_id;

	char *log_prefix;
	unsigned int log_prefixes_dropped;
	event_log_prefix_callback_t *log_prefix_callback;
	void *log_prefix_callback_context;
	event_log_message_callback_t *log_message_callback;
	void *log_message_callback_context;
	ARRAY(struct event_pointer) pointers;
	enum log_type min_log_level;
	bool log_prefix_from_system_pool:1;
	bool log_prefix_replace:1;
	bool passthrough:1;
	bool forced_debug:1;
	bool always_log_source:1;
	bool sending_debug_log:1;
	bool debug_level_checked:1;

/* Fields that are exported & imported: */
	struct timeval tv_created_ioloop;
	struct timeval tv_created;
	struct timeval tv_last_sent;

	const char *source_filename;
	unsigned int source_linenum;

	/* This is the event's name while it's being sent. It'll be removed
	   after the event is sent. */
	char *sending_name;

	ARRAY(struct event_category *) categories;
	ARRAY(struct event_field) fields;
};

enum event_callback_type {
	/* Event was just created */
	EVENT_CALLBACK_TYPE_CREATE,
	/* Event is being sent */
	EVENT_CALLBACK_TYPE_SEND,
	/* Event is being freed */
	EVENT_CALLBACK_TYPE_FREE,
};

/* Returns TRUE if the event should continue to the next handler. Unless
   stopped, the final handler logs the event if it matches the log filter. */
typedef bool event_callback_t(struct event *event,
			      enum event_callback_type type,
			      struct failure_context *ctx,
			      const char *fmt, va_list args);
/* Called when category is registered or unregistered. The parent category
   is always already registered. */
typedef void event_category_callback_t(struct event_category *category);

void event_send(struct event *event, struct failure_context *ctx,
		const char *fmt, ...) ATTR_FORMAT(3, 4);
void event_vsend(struct event *event, struct failure_context *ctx,
		 const char *fmt, va_list args) ATTR_FORMAT(3, 0);

struct event *events_get_head(void);

/* Find event category by name. This only finds registered categories. */
struct event_category *event_category_find_registered(const char *name);
/* Return all registered categories. */
struct event_category *const *
event_get_registered_categories(unsigned int *count_r);

/* Register callback to be called for event's different states. */
void event_register_callback(event_callback_t *callback);
void event_unregister_callback(event_callback_t *callback);

/* Register callback to be called whenever categories are registered or
   unregistered. */
void event_category_register_callback(event_category_callback_t *callback);
void event_category_unregister_callback(event_category_callback_t *callback);

#endif
