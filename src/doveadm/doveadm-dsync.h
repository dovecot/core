#ifndef DOVEADM_DSYNC_H
#define DOVEADM_DSYNC_H

#include "doveadm-mail.h" /* for struct doveadm_mail_cmd_context */
#include "dsync-brain.h"  /* for enum dsync_brain_sync_type */
/* we have to include dsync-brain.h without "dsync/" as the headers
   are installed in a flat directory. CPPFLAGS have been extended with
   corresponding '-I$(top_srcdir)/src/doveadm/dsync' switch */

extern struct doveadm_cmd_ver2 doveadm_cmd_dsync_mirror;
extern struct doveadm_cmd_ver2 doveadm_cmd_dsync_backup;
extern struct doveadm_cmd_ver2 doveadm_cmd_dsync_server;

enum dsync_run_type {
	DSYNC_RUN_TYPE_LOCAL,
	DSYNC_RUN_TYPE_STREAM,
	DSYNC_RUN_TYPE_CMD
};

struct dsync_module_hooks;

struct dsync_module_context {
	const struct dsync_module_hooks *module_hooks;
	void *ctx;
};
ARRAY_DEFINE_TYPE(dsync_module_context, struct dsync_module_context *);

struct dsync_cmd_context {
	struct doveadm_mail_cmd_context ctx;
	enum dsync_brain_sync_type sync_type;
	const char *mailbox;
	const char *const *destination;
	const char *const *destination_options;
	const char *sync_flags;
	const char *virtual_all_box;
	guid_128_t mailbox_guid;
	const char *state_input, *rawlog_path;
	ARRAY_TYPE(const_string) exclude_mailboxes;
	ARRAY_TYPE(const_string) namespace_prefixes;
	ARRAY_TYPE(dsync_module_context) hooks;
	time_t sync_since_timestamp;
	time_t sync_until_timestamp;
	uoff_t sync_max_size;
	unsigned int io_timeout_secs;

	const char *remote_name;
	pid_t remote_pid;
	const char *const *remote_cmd_args;
	struct child_wait *child_wait;
	int exit_status;

	int fd_in, fd_out, fd_err;
	struct io *io_err;
	struct istream *input, *err_stream;
	struct ostream *output;
	size_t input_orig_bufsize, output_orig_bufsize;
	const char *err_prefix;
	struct failure_context failure_ctx;

	struct ssl_iostream *ssl_iostream;

	enum dsync_run_type run_type;
	struct doveadm_client *tcp_conn;
	const char *error;

	unsigned int lock_timeout;
	unsigned int import_commit_msgs_interval;

	bool lock:1;
	bool purge_remote:1;
	bool sync_visible_namespaces:1;
	bool oneway:1;
	bool backup:1;
	bool reverse_backup:1;
	bool remote_user_prefix:1;
	bool no_mail_sync:1;
	bool exited:1;
	bool empty_hdr_workaround:1;
	bool no_header_hashes:1;
	bool err_line_continues:1;
};

struct dsync_hooks {
        /* allows dsync plugins to allocating own context. Use given
           dsync_cmd_context dctx to access the pool of
           doveadm_mail_cmd_context dctx->ctx. Return allocated context
           as void pointer. Use dealloc hook to free allocated memory.
           If not specified, plugin context pointer will be NULL in
           all remaining hook parameters.
           All further hooks will be called with the returned context
           pointer and the current dsync_cmd_context.
        */
	void *(*alloc)(struct dsync_cmd_context *dctx);
        /* free dsync plugin's own context allocated in alloc hook.
        */
	void (*deinit)(void *ctx, struct dsync_cmd_context *dctx);

        /* allows dsync plugins to do an init. The hook is called at
           the end of cmd_dsync_init().
        */
	void (*init)(void *ctx,
                     struct dsync_cmd_context *dctx);

        /* allows dsync plugins to do handle an unknown
           doveadm_server_reply. The hook is called before the generic
           UNKNOWN handling in dsync_connected_callback().
           If the plugin has handling the reply, it must return TRUE to
           indicate, that dsync_connected_callback() should not handle
           the reply as unknown.
           The doveadm_server_reply received by dsync_connected_callback()
           is given as parameters.
        */
        bool (*connected_callback)(void *ctx,
                                   struct dsync_cmd_context *dctx,
                                   const struct doveadm_server_reply *reply);
        /* allows dsync plugins to do react BEFORE running dsync. The hook
           is called at the beginning of cmd_dsync_run().
           The mail_user received by cmd_dsync_run() is given as parameter.
        */
        int (*run_pre)(void *ctx,
                       struct dsync_cmd_context *dctx,
                       struct mail_user *user);

        /* allows dsync plugins to do an init for dsync-server. The
           hook is called at the end of cmd_dsync_server_init().
        */
	void (*server_init)(void *ctx,
                            struct dsync_cmd_context *dctx);
        /* allows dsync plugins to do react BEFORE running dsync on the
           server. The hook is called at the beginning of
           cmd_dsync_server_run().
           The mail_user received by cmd_dsync_server_run() is given as parameter.
        */
        int (*server_run_pre)(void *ctx,
                              struct dsync_cmd_context *dctx,
                              struct mail_user *user);
        /* allows dsync plugins to do react AFTER dsync on the
           server. The hook is called after dsync has been completed but
           before dsync_ibc and dsync_brain are freed in
           cmd_dsync_server_run().
           The mail_user received by cmd_dsync_server_run() is given as
           parameter as well as the dsync_ibc and dsync_brain.
           The plugin may store the sync results in it's own context to use
           in server_run_deinit hook.
        */
	void (*server_run_post)(void *ctx,
                                struct dsync_cmd_context *dctx,
                                struct mail_user *user,
                                struct dsync_ibc *ibc,
                                struct dsync_brain *brain);
        /* allows dsync plugins to do react AT THE END of dsync on the
           server. The hook is called at the end of cmd_dsync_server_run().
           The mail_user received by cmd_dsync_server_run() is given as
           parameter.
           The plugin may use the sync results in it's own context and the
           exit_code set in dctx->ctx.exit_code to do it's own post
           processing.
        */
	void (*server_run_end)(void *ctx,
                               struct dsync_cmd_context *dctx,
                               struct mail_user *user);

        /* allows dsync plugins to modify the dsync-server command send
           to the server. The hook is called in dsync_server_run_command()
           after the command has been build but before the final newline
           is appended.
           The doveadm_client received by dsync_server_run_command() and
           the cmd are given as parameters.
           The cmd may be modified by this function, therefore it is
           provided non-const.
        */
	void (*server_run_command)(void *ctx,
                                   struct dsync_cmd_context *dctx,
                                   struct doveadm_client *conn,
                                   string_t *cmd);
};


/* use this function in your doveadm dsync plugin to register hooks
   during dsync/dsync-server. See struct dsync_hooks for a description
   of possible hook functions. */
void dsync_hooks_add(const struct module *module,
                     const struct dsync_hooks *hooks);
/* in case your doveadm dsync plugin registered hooks, you can
   unregister them using this function. */
void dsync_hooks_remove(const struct dsync_hooks *hooks);

#endif
