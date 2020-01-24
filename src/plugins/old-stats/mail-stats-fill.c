/* Copyright (c) 2011-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "time-util.h"
#include "stats-plugin.h"
#include "mail-stats.h"

#include <sys/resource.h>

#define PROC_IO_PATH "/proc/self/io"

static bool proc_io_disabled = FALSE;
static int proc_io_fd = -1;

static int
process_io_buffer_parse(const char *buf, struct mail_stats *stats)
{
	const char *const *tmp;

	tmp = t_strsplit(buf, "\n");
	for (; *tmp != NULL; tmp++) {
		if (str_begins(*tmp, "rchar: ")) {
			if (str_to_uint64(*tmp + 7, &stats->read_bytes) < 0)
				return -1;
		} else if (str_begins(*tmp, "wchar: ")) {
			if (str_to_uint64(*tmp + 7, &stats->write_bytes) < 0)
				return -1;
		} else if (str_begins(*tmp, "syscr: ")) {
			if (str_to_uint32(*tmp + 7, &stats->read_count) < 0)
				return -1;
		} else if (str_begins(*tmp, "syscw: ")) {
			if (str_to_uint32(*tmp + 7, &stats->write_count) < 0)
				return -1;
		}
	}
	return 0;
}

static int process_io_open(void)
{
	uid_t uid;

	if (proc_io_fd != -1)
		return proc_io_fd;

	if (proc_io_disabled)
		return -1;

	proc_io_fd = open(PROC_IO_PATH, O_RDONLY);
	if (proc_io_fd == -1 && errno == EACCES) {
		/* kludge: if we're running with permissions temporarily
		   dropped, get them temporarily back so we can open
		   /proc/self/io. */
		uid = geteuid();
		if (seteuid(0) == 0) {
			proc_io_fd = open(PROC_IO_PATH, O_RDONLY);
			if (seteuid(uid) < 0) {
				/* oops, this is bad */
				i_fatal("stats: seteuid(%s) failed", dec2str(uid));
			}
		}
		errno = EACCES;
	}
	if (proc_io_fd == -1) {
		/* ignore access errors too, certain security options can
		   prevent root access to this file when not owned by root */
		if (errno != ENOENT && errno != EACCES)
			i_error("open(%s) failed: %m", PROC_IO_PATH);
		proc_io_disabled = TRUE;
		return -1;
	}
	return proc_io_fd;
}

static void process_read_io_stats(struct mail_stats *stats)
{
	char buf[1024];
	int fd, ret;

	if ((fd = process_io_open()) == -1)
		return;

	ret = pread(fd, buf, sizeof(buf), 0);
	if (ret <= 0) {
		if (ret == -1)
			i_error("read(%s) failed: %m", PROC_IO_PATH);
		else
			i_error("read(%s) returned EOF", PROC_IO_PATH);
	} else if (ret == sizeof(buf)) {
		/* just shouldn't happen.. */
		i_error("%s is larger than expected", PROC_IO_PATH);
		proc_io_disabled = TRUE;
	} else {
		buf[ret] = '\0';
		T_BEGIN {
			if (process_io_buffer_parse(buf, stats) < 0) {
				i_error("Invalid input in file %s",
					PROC_IO_PATH);
				proc_io_disabled = TRUE;
			}
		} T_END;
	}
}

static void
user_trans_stats_get(struct stats_user *suser, struct mail_stats *dest_r)
{
	struct stats_transaction_context *strans;

	mail_stats_add_transaction(dest_r, &suser->finished_transaction_stats);
	for (strans = suser->transactions; strans != NULL; strans = strans->next)
		mail_stats_add_transaction(dest_r, &strans->trans->stats);
}

void mail_stats_fill(struct stats_user *suser, struct mail_stats *stats_r)
{
	static bool getrusage_broken = FALSE;
	static struct rusage prev_usage;
	struct rusage usage;

	i_zero(stats_r);
	/* cputime */
	if (getrusage(RUSAGE_SELF, &usage) < 0) {
		if (!getrusage_broken) {
			i_error("getrusage() failed: %m");
			getrusage_broken = TRUE;
		}
		usage = prev_usage;
	} else if (timeval_diff_usecs(&usage.ru_stime, &prev_usage.ru_stime) < 0) {
		/* This seems to be a Linux bug. */
		usage.ru_stime = prev_usage.ru_stime;
	}
	prev_usage = usage;

	stats_r->user_cpu = usage.ru_utime;
	stats_r->sys_cpu = usage.ru_stime;
	stats_r->min_faults = usage.ru_minflt;
	stats_r->maj_faults = usage.ru_majflt;
	stats_r->vol_cs = usage.ru_nvcsw;
	stats_r->invol_cs = usage.ru_nivcsw;
	stats_r->disk_input = (unsigned long long)usage.ru_inblock * 512ULL;
	stats_r->disk_output = (unsigned long long)usage.ru_oublock * 512ULL;
	i_gettimeofday(&stats_r->clock_time);
	process_read_io_stats(stats_r);
	user_trans_stats_get(suser, stats_r);
}

void mail_stats_global_preinit(void)
{
	(void)process_io_open();
}

void mail_stats_fill_global_deinit(void)
{
	i_close_fd(&proc_io_fd);
}
