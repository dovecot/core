#ifndef MAIL_STATS_H
#define MAIL_STATS_H

#include <sys/time.h>
#include "mail-storage-private.h"

struct stats_user;

struct mail_stats {
	/* user/system CPU time used */
	struct timeval user_cpu, sys_cpu;
	/* clock time used (not counting the time in ioloop wait) */
	struct timeval clock_time;
	/* minor / major page faults */
	uint32_t min_faults, maj_faults;
	/* voluntary / involuntary context switches */
	uint32_t vol_cs, invol_cs;
	/* disk input/output bytes */
	uint64_t disk_input, disk_output;
	/* read()/write() syscall count and number of bytes */
	uint32_t read_count, write_count;
	uint64_t read_bytes, write_bytes;

	/* based on struct mailbox_transaction_stats: */
	uint32_t trans_lookup_path;
	uint32_t trans_lookup_attr;
	uint32_t trans_files_read_count;
	uint64_t trans_files_read_bytes;
	uint64_t trans_cache_hit_count;
};

extern const struct stats_vfuncs mail_stats_vfuncs;

void mail_stats_fill(struct stats_user *suser, struct mail_stats *mail_stats);
void mail_stats_add_transaction(struct mail_stats *stats,
				const struct mailbox_transaction_stats *trans_stats);

void mail_stats_global_preinit(void);
void mail_stats_fill_global_deinit(void);

#endif
