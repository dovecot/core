#ifndef DOVEADM_MAIL_H
#define DOVEADM_MAIL_H

#include <stdio.h>
#include "doveadm.h"
#include "doveadm-util.h"
#include "module-context.h"
#include "mail-error.h"
#include "mail-storage.h"
#include "mail-storage-service.h"

struct mailbox;
struct mailbox_list;
struct mail_storage;
struct mail_user;
struct doveadm_mail_cmd_context;

struct doveadm_mail_cmd_vfuncs {
	/* Parse one getopt() parameter. This is called for each parameter. */
	bool (*parse_arg)(struct doveadm_mail_cmd_context *ctx, int c);
	/* Usually not needed. The preinit() is called just after parsing all
	   parameters, but before any userdb lookups are done. This allows the
	   preinit() to alter the userdb lookup behavior (especially
	   service_flags). */
	void (*preinit)(struct doveadm_mail_cmd_context *ctx);
	/* Initialize the command. Most importantly if the function prints
	   anything, this should initialize the headers. It shouldn't however
	   do any actual work. The init() is called also when doveadm is
	   performing the work via doveadm-server, which could be running
	   remotely with completely different Dovecot configuration. */
	void (*init)(struct doveadm_mail_cmd_context *ctx,
		     const char *const args[]);
	/* Usually not needed. When iterating through multiple users, use this
	   function to get the next username. Overriding this is usually done
	   only when there's a known username filter, such as the expire
	   plugin. */
	int (*get_next_user)(struct doveadm_mail_cmd_context *ctx,
			     const char **username_r);
	/* Usually not needed. This is called between
	   mail_storage_service_lookup() and mail_storage_service_next() for
	   each user. */
	int (*prerun)(struct doveadm_mail_cmd_context *ctx,
		      struct mail_storage_service_user *service_user,
		      const char **error_r);
	/* This is the main function which performs all the work for the
	   command. This is called once per each user. */
	int (*run)(struct doveadm_mail_cmd_context *ctx,
		   struct mail_user *mail_user);
	/* Deinitialize the command. Called once at the end - even if
	   preinit() or init() was never called. */
	void (*deinit)(struct doveadm_mail_cmd_context *ctx);
};

struct doveadm_mail_cmd_module_register {
	unsigned int id;
};

union doveadm_mail_cmd_module_context {
        struct doveadm_mail_cmd_vfuncs super;
	struct doveadm_mail_cmd_module_register *reg;
};

struct doveadm_mail_cmd_context {
	pool_t pool;
	struct doveadm_cmd_context *cctx;
	const struct doveadm_mail_cmd *cmd;
	const char *const *args;
	/* args including -options */
	const char *const *full_args;

	const char *getopt_args;
	const struct doveadm_settings *set;
	enum mail_storage_service_flags service_flags;
	enum mailbox_transaction_flags transaction_flags;
	struct mail_storage_service_ctx *storage_service;
	struct mail_storage_service_input storage_service_input;
	/* search args aren't set for all mail commands */
	struct mail_search_args *search_args;
	struct istream *users_list_input;

	struct mail_storage_service_user *cur_service_user;
	struct mail_user *cur_mail_user;
	struct doveadm_mail_cmd_vfuncs v;

	struct istream *cmd_input;
	int cmd_input_fd;

	ARRAY(union doveadm_mail_cmd_module_context *) module_contexts;

	/* if non-zero, exit with this code */
	int exit_code;

	/* This command is being called by a remote doveadm client. */
	bool proxying:1;
	/* We're handling only a single user */
	bool iterate_single_user:1;
	/* We're going through all users (not set for wildcard usernames) */
	bool iterate_all_users:1;
	/* Add username header to all replies */
	bool add_username_header:1;
};

struct doveadm_mail_cmd {
	struct doveadm_mail_cmd_context *(*alloc)(void);
	const char *name;
	const char *usage_args;
};
ARRAY_DEFINE_TYPE(doveadm_mail_cmd, struct doveadm_mail_cmd);

extern ARRAY_TYPE(doveadm_mail_cmd) doveadm_mail_cmds;
extern void (*hook_doveadm_mail_init)(struct doveadm_mail_cmd_context *ctx);
extern struct doveadm_mail_cmd_module_register doveadm_mail_cmd_module_register;
extern char doveadm_mail_cmd_hide;

bool doveadm_is_killed(void);
int doveadm_killed_signo(void);

bool doveadm_mail_try_run(const char *cmd_name, int argc, char *argv[]);
void doveadm_mail_register_cmd(const struct doveadm_mail_cmd *cmd);
const struct doveadm_mail_cmd *doveadm_mail_cmd_find(const char *cmd_name);

void doveadm_mail_usage(string_t *out);
void doveadm_mail_help(const struct doveadm_mail_cmd *cmd) ATTR_NORETURN;
void doveadm_mail_help_name(const char *cmd_name) ATTR_NORETURN;
void doveadm_mail_try_help_name(const char *cmd_name);
bool doveadm_mail_has_subcommands(const char *cmd_name);

void doveadm_mail_init(void);
void doveadm_mail_deinit(void);

const struct doveadm_mail_cmd *
doveadm_mail_cmd_find_from_argv(const char *cmd_name, int *argc,
				const char *const **argv);
struct doveadm_mail_cmd_context *
doveadm_mail_cmd_init(const struct doveadm_mail_cmd *cmd,
		      const struct doveadm_settings *set);
int doveadm_mail_single_user(struct doveadm_mail_cmd_context *ctx,
			     const char **error_r);
int doveadm_mail_server_user(struct doveadm_mail_cmd_context *ctx,
			     const struct mail_storage_service_input *input,
			     const char **error_r);
void doveadm_mail_server_flush(void);

/* Request input stream to be read (from stdin). This must be called from
   the command's init() function. */
void doveadm_mail_get_input(struct doveadm_mail_cmd_context *ctx);

struct mailbox *
doveadm_mailbox_find(struct mail_user *user, const char *mailbox);
struct mail_search_args *
doveadm_mail_build_search_args(const char *const args[]);
void doveadm_mailbox_args_check(const char *const args[]);
struct mail_search_args *
doveadm_mail_mailbox_search_args_build(const char *const args[]);

void expunge_search_args_check(struct mail_search_args *args, const char *cmd);

struct doveadm_mail_cmd_context *
doveadm_mail_cmd_alloc_size(size_t size);
#define doveadm_mail_cmd_alloc(type) \
	(type *)doveadm_mail_cmd_alloc_size(sizeof(type))

void doveadm_mail_failed_error(struct doveadm_mail_cmd_context *ctx,
			       enum mail_error error);
void doveadm_mail_failed_storage(struct doveadm_mail_cmd_context *ctx,
				 struct mail_storage *storage);
void doveadm_mail_failed_mailbox(struct doveadm_mail_cmd_context *ctx,
				 struct mailbox *box);
void doveadm_mail_failed_list(struct doveadm_mail_cmd_context *ctx,
			      struct mailbox_list *list);

extern struct doveadm_mail_cmd cmd_batch;

extern struct doveadm_cmd_ver2 doveadm_cmd_mailbox_metadata_set_ver2;
extern struct doveadm_cmd_ver2 doveadm_cmd_mailbox_metadata_unset_ver2;
extern struct doveadm_cmd_ver2 doveadm_cmd_mailbox_metadata_get_ver2;
extern struct doveadm_cmd_ver2 doveadm_cmd_mailbox_metadata_list_ver2;
extern struct doveadm_cmd_ver2 doveadm_cmd_mailbox_status_ver2;
extern struct doveadm_cmd_ver2 doveadm_cmd_mailbox_list_ver2;
extern struct doveadm_cmd_ver2 doveadm_cmd_mailbox_create_ver2;
extern struct doveadm_cmd_ver2 doveadm_cmd_mailbox_delete_ver2;
extern struct doveadm_cmd_ver2 doveadm_cmd_mailbox_rename_ver2;
extern struct doveadm_cmd_ver2 doveadm_cmd_mailbox_subscribe_ver2;
extern struct doveadm_cmd_ver2 doveadm_cmd_mailbox_unsubscribe_ver2;
extern struct doveadm_cmd_ver2 doveadm_cmd_fetch_ver2;
extern struct doveadm_cmd_ver2 doveadm_cmd_save_ver2;
extern struct doveadm_cmd_ver2 doveadm_cmd_index_ver2;
extern struct doveadm_cmd_ver2 doveadm_cmd_altmove_ver2;
extern struct doveadm_cmd_ver2 doveadm_cmd_deduplicate_ver2;
extern struct doveadm_cmd_ver2 doveadm_cmd_expunge_ver2;
extern struct doveadm_cmd_ver2 doveadm_cmd_flags_add_ver2;
extern struct doveadm_cmd_ver2 doveadm_cmd_flags_remove_ver2;
extern struct doveadm_cmd_ver2 doveadm_cmd_flags_replace_ver2;
extern struct doveadm_cmd_ver2 doveadm_cmd_import_ver2;
extern struct doveadm_cmd_ver2 doveadm_cmd_search_ver2;
extern struct doveadm_cmd_ver2 doveadm_cmd_copy_ver2;
extern struct doveadm_cmd_ver2 doveadm_cmd_move_ver2;
extern struct doveadm_cmd_ver2 doveadm_cmd_mailbox_update_ver2;
extern struct doveadm_cmd_ver2 doveadm_cmd_mailbox_path_ver2;
extern struct doveadm_cmd_ver2 doveadm_cmd_mailbox_cache_decision;
extern struct doveadm_cmd_ver2 doveadm_cmd_mailbox_cache_remove;
extern struct doveadm_cmd_ver2 doveadm_cmd_mailbox_cache_purge;
extern struct doveadm_cmd_ver2 doveadm_cmd_rebuild_attachments;

#define DOVEADM_CMD_MAIL_COMMON \
DOVEADM_CMD_PARAM('A', "all-users", CMD_PARAM_BOOL, 0) \
DOVEADM_CMD_PARAM('S', "socket-path", CMD_PARAM_STR, 0) \
DOVEADM_CMD_PARAM('u', "user", CMD_PARAM_STR, 0) \
DOVEADM_CMD_PARAM('\0', "trans-flags", CMD_PARAM_INT64, 0) \
DOVEADM_CMD_PARAM('F', "user-file", CMD_PARAM_ISTREAM, 0)

#define DOVEADM_CMD_MAIL_USAGE_PREFIX \
	"[-u <user>|-A] [-S <socket_path>] "

#endif
