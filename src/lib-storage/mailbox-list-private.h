#ifndef MAILBOX_LIST_PRIVATE_H
#define MAILBOX_LIST_PRIVATE_H

#include "mail-namespace.h"
#include "mailbox-list.h"

struct dirent;

struct mailbox_list_vfuncs {
	struct mailbox_list *(*alloc)(void);
	void (*deinit)(struct mailbox_list *list);

	bool (*is_valid_pattern)(struct mailbox_list *list,
				 const char *pattern);
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
	const char *(*join_refpattern)(struct mailbox_list *list,
				       const char *ref, const char *pattern);

	struct mailbox_list_iterate_context *
		(*iter_init)(struct mailbox_list *list,
			     const char *const *patterns,
			     enum mailbox_list_iter_flags flags);
	const struct mailbox_info *
		(*iter_next)(struct mailbox_list_iterate_context *ctx);
	int (*iter_deinit)(struct mailbox_list_iterate_context *ctx);

	/* Returns -1 if error, 0 if it's not a valid mailbox, 1 if it is.
	   flags may be updated (especially the children flags). */
	int (*iter_is_mailbox)(struct mailbox_list_iterate_context *ctx,
			       const char *dir, const char *fname,
			       enum mailbox_list_file_type type,
			       enum mailbox_info_flags *flags_r);

	int (*set_subscribed)(struct mailbox_list *list,
			      const char *name, bool set);
	int (*delete_mailbox)(struct mailbox_list *list, const char *name);
	int (*rename_mailbox)(struct mailbox_list *list, const char *oldname,
			      const char *newname);
};

struct mailbox_list_module_register {
	unsigned int id;
};

union mailbox_list_module_context {
	struct mailbox_list_vfuncs super;
	struct mailbox_list_module_register *reg;
};

struct mailbox_list {
	const char *name;
	char hierarchy_sep;
	size_t mailbox_name_max_length;

	struct mailbox_list_vfuncs v;

/* private: */
	pool_t pool;
	struct mail_namespace *ns;
	struct mailbox_list_settings set;
	enum mailbox_list_flags flags;

	/* -1 if unset: */
	uid_t cached_uid;
	gid_t cached_gid;

	char *error_string;
	enum mail_error error;
	bool temporary_error;

	ARRAY_DEFINE(module_contexts, union mailbox_list_module_context *);
};

struct mailbox_list_iterate_context {
	struct mailbox_list *list;
	enum mailbox_list_iter_flags flags;
	bool failed;
};

/* Modules should use do "my_id = mailbox_list_module_id++" and
   use objects' module_contexts[id] for their own purposes. */
extern struct mailbox_list_module_register mailbox_list_module_register;

extern void (*hook_mailbox_list_created)(struct mailbox_list *list);

int mailbox_list_delete_index_control(struct mailbox_list *list,
				      const char *name);

bool mailbox_list_name_is_too_large(const char *name, char sep);
enum mailbox_list_file_type mailbox_list_get_file_type(const struct dirent *d);

void mailbox_list_clear_error(struct mailbox_list *list);
void mailbox_list_set_error(struct mailbox_list *list,
			    enum mail_error error, const char *string);
void mailbox_list_set_critical(struct mailbox_list *list, const char *fmt, ...)
	__attr_format__(2, 3);
void mailbox_list_set_internal_error(struct mailbox_list *list);
bool mailbox_list_set_error_from_errno(struct mailbox_list *list);

#endif
