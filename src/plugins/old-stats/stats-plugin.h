#ifndef STATS_PLUGIN_H
#define STATS_PLUGIN_H

#include "module-context.h"
#include "mail-user.h"
#include "mail-storage-private.h"

#define STATS_USER_CONTEXT(obj) \
	MODULE_CONTEXT(obj, stats_user_module)

#define STATS_USER_CONTEXT_REQUIRE(obj) \
	MODULE_CONTEXT_REQUIRE(obj, stats_user_module)

struct stats_user {
	union mail_user_module_context module_ctx;

	struct ioloop_context *ioloop_ctx;
	struct stats_connection *stats_conn;
	const char *stats_session_id;
	bool stats_connected;

	unsigned int refresh_secs;
	bool track_commands;
	unsigned int refresh_check_counter;

	/* current session statistics */
	struct stats *session_stats;
	/* cumulative trans_stats for all already freed transactions. */
	struct mailbox_transaction_stats finished_transaction_stats;
	/* stats before calling IO callback. after IO callback this value is
	   compared to current stats to see the difference */
	struct stats *pre_io_stats;

	time_t last_session_update;
	struct timeout *to_stats_timeout;
	/* stats that were last sent to stats server */
	struct stats *last_sent_session_stats;
	bool session_sent_duplicate;

	/* list of all currently existing transactions for this user */
	struct stats_transaction_context *transactions;
};

struct stats_transaction_context {
	union mailbox_transaction_module_context module_ctx;

	struct stats_transaction_context *prev, *next;
	struct mailbox_transaction_context *trans;

	struct mailbox_transaction_stats prev_stats;
};

extern MODULE_CONTEXT_DEFINE(stats_user_module, &mail_user_module_register);
extern MODULE_CONTEXT_DEFINE(stats_storage_module, &mail_storage_module_register);

void old_stats_plugin_init(struct module *module);
void old_stats_plugin_preinit(void);
void old_stats_plugin_deinit(void);

#endif
