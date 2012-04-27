#ifndef STATS_PLUGIN_H
#define STATS_PLUGIN_H

#include "module-context.h"
#include "guid.h"
#include "mail-user.h"
#include "mail-storage-private.h"

#include <sys/time.h>

#define STATS_USER_CONTEXT(obj) \
	MODULE_CONTEXT(obj, stats_user_module)

struct mail_stats {
	/* user/system CPU time used */
	struct timeval user_cpu, sys_cpu;
	/* minor / major page faults */
	uint32_t min_faults, maj_faults;
	/* voluntary / involuntary context switches */
	uint32_t vol_cs, invol_cs;
	/* disk input/output bytes */
	uint64_t disk_input, disk_output;
	/* read()/write() syscall count and number of bytes */
	uint32_t read_count, write_count;
	uint64_t read_bytes, write_bytes;
	struct mailbox_transaction_stats trans_stats;
};

struct stats_user {
	union mail_user_module_context module_ctx;

	struct ioloop_context *ioloop_ctx;
	struct stats_connection *stats_conn;
	guid_128_t session_guid;

	unsigned int refresh_secs;
	bool track_commands;
	unsigned int refresh_check_counter;

	/* current session statistics */
	struct mail_stats session_stats;
	/* stats before calling IO callback. after IO callback this value is
	   compared to current stats to see the difference */
	struct mail_stats pre_io_stats;

	time_t last_session_update;
	struct timeout *to_stats_timeout;
	/* stats that were last sent to stats server */
	struct mail_stats last_sent_session_stats;
	bool session_sent_duplicate;

	/* list of all currently existing transactions for this user */
	struct stats_transaction_context *transactions;
};

extern MODULE_CONTEXT_DEFINE(stats_user_module, &mail_user_module_register);

void mail_stats_get(struct stats_user *suser, struct mail_stats *stats_r);
void mail_stats_add_diff(struct mail_stats *dest,
			 const struct mail_stats *old_stats,
			 const struct mail_stats *new_stats);
void mail_stats_export(string_t *str, const struct mail_stats *stats);

void stats_plugin_init(struct module *module);
void stats_plugin_deinit(void);

#endif
