#ifndef __MAILBOX_LIST_PRIVATE_H
#define __MAILBOX_LIST_PRIVATE_H

#include "mailbox-list.h"

struct dirent;

struct mailbox_list_vfuncs {
	struct mailbox_list *(*alloc)(void);
	void (*deinit)(struct mailbox_list *list);

	bool (*is_valid_mask)(struct mailbox_list *list, const char *mask);
	bool (*is_valid_existing_name)(struct mailbox_list *list,
				       const char *name);
	bool (*is_valid_create_name)(struct mailbox_list *list,
				     const char *name);

	const char *(*get_path)(struct mailbox_list *list, const char *name,
				enum mailbox_list_path_type type);
	int (*get_mailbox_name_status)(struct mailbox_list *list,
				       const char *name,
				       enum mailbox_name_status *status);

	const char *(*get_temp_prefix)(struct mailbox_list *list);

	struct mailbox_list_iterate_context *
		(*iter_init)(struct mailbox_list *list,
			     const char *ref, const char *mask,
			     enum mailbox_list_iter_flags flags);
	struct mailbox_info *
		(*iter_next)(struct mailbox_list_iterate_context *ctx);
	int (*iter_deinit)(struct mailbox_list_iterate_context *ctx);

	int (*set_subscribed)(struct mailbox_list *list,
			      const char *name, bool set);
};

struct mailbox_list {
	const char *name;
	char hierarchy_sep;
	size_t mailbox_name_max_length;

	struct mailbox_list_vfuncs v;

/* private: */
	pool_t pool;
	struct mailbox_list_settings set;
	enum mailbox_list_flags flags;

	char *error;
	bool temporary_error;

	mailbox_list_is_mailbox_t *callback;
	void *context;

	ARRAY_DEFINE(module_contexts, void);
};

struct mailbox_list_iterate_context {
	struct mailbox_list *list;
	enum mailbox_list_iter_flags flags;
	bool failed;
};

/* Modules should use do "my_id = mailbox_list_module_id++" and
   use objects' module_contexts[id] for their own purposes. */
extern unsigned int mailbox_list_module_id;

extern void (*hook_mailbox_list_created)(struct mailbox_list *list);

bool mailbox_list_name_is_too_large(const char *name, char sep);
enum mailbox_list_file_type mailbox_list_get_file_type(const struct dirent *d);

void mailbox_list_clear_error(struct mailbox_list *list);
void mailbox_list_set_error(struct mailbox_list *list, const char *error);
void mailbox_list_set_critical(struct mailbox_list *list, const char *fmt, ...)
	__attr_format__(2, 3);

#endif
