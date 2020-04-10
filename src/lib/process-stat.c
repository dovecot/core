/* Copyright (c) 2008-2021 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "process-stat.h"
#include "time-util.h"
#include <limits.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/time.h>
#include <time.h>
#include <sys/resource.h>
#include <stdio.h>

#define PROC_STAT_PATH "/proc/self/stat"
#define PROC_STATUS_PATH "/proc/self/status"
#define PROC_IO_PATH "/proc/self/io"

static const uint64_t stat_undefined = 0xFFFFFFFFFFFFFFFF;

struct key_val {
	const char *key;
	uint64_t *value;
	unsigned int idx;
};

static int parse_field(const char *line, struct key_val *field)
{
	if (str_begins_with(line, field->key))
		return str_to_uint64(line + strlen(field->key), field->value);
	return -1;
}

static void buffer_parse(const char *buf, struct key_val *fields)
{
	const char *const *tmp;
	tmp = t_strsplit(buf, "\n");
	unsigned int tmp_count = str_array_length(tmp);
	for (; fields->key != NULL; fields++) {
		if (fields->idx >= tmp_count ||
		    parse_field(tmp[fields->idx], fields) < 0)
			*fields->value = stat_undefined;
	}
}

static int open_fd(const char *path, struct event *event)
{
	int fd;
	uid_t uid;

	fd = open(path, O_RDONLY);

	if (fd == -1 && errno == EACCES) {
		uid = geteuid();
		/* kludge: if we're running with permissions temporarily
		   dropped, get them temporarily back so we can open
		   /proc/self/io. */
		if (seteuid(0) == 0) {
			fd = open(path, O_RDONLY);
			if (seteuid(uid) < 0)
				i_fatal("seteuid(%s) failed", dec2str(uid));
		}
		errno = EACCES;
	}
	if (fd == -1) {
		if (errno == ENOENT || errno == EACCES)
			e_debug(event, "open(%s) failed: %m", path);
		else
			e_error(event, "open(%s) failed: %m", path);
	}
	return fd;
}

static int
read_file(int fd, const char *path, char *buf_r, size_t buf_size, struct event *event)
{
	ssize_t ret;
	ret = read(fd, buf_r, buf_size);
	if (ret <= 0) {
		if (ret == -1)
			e_error(event, "read(%s) failed: %m", path);
		else
			e_error(event, "read(%s) returned EOF", path);
	} else if (ret == (ssize_t)buf_size) {
		e_error(event, "%s is larger than expected", path);
		buf_r[buf_size - 1] = '\0';
	} else {
		buf_r[ret] = '\0';
	}
	i_close_fd(&fd);
	return ret <= 0 ? -1 : 0;
}

static int parse_key_val_file(const char *path,
			      struct key_val *fields,
			      struct event *event)
{
	char buf[2048];
	int fd;

	fd = open_fd(path, event);
	if (fd == -1 || read_file(fd, path, buf, sizeof(buf), event) < 0) {
		for (; fields->key != NULL; fields++)
			*fields->value = stat_undefined;
		return -1;
	}
	buffer_parse(buf, fields);
	return 0;
}

static int parse_proc_io(struct process_stat *stat_r, struct event *event)
{
	struct key_val fields[] = {
		{ "rchar: ", &stat_r->rchar, 0 },
		{ "wchar: ", &stat_r->wchar, 1 },
		{ "syscr: ", &stat_r->syscr, 2 },
		{ "syscw: ", &stat_r->syscw, 3 },
		{ NULL, NULL, 0 },
	};
	if (stat_r->proc_io_failed ||
	    parse_key_val_file(PROC_IO_PATH, fields, event) < 0) {
		stat_r->proc_io_failed = TRUE;
		return -1;
	}
	return 0;
}

static int parse_proc_status(struct process_stat *stat_r, struct event *event)
{
	struct key_val fields [] = {
		{ "voluntary_ctxt_switches:\t", &stat_r->vol_cs, 53 },
		{ "nonvoluntary_ctxt_switches:\t", &stat_r->invol_cs, 54 },
		{ NULL, NULL, 0 },
	};
	if (stat_r->proc_status_failed ||
	    parse_key_val_file(PROC_STATUS_PATH, fields, event) < 0) {
		stat_r->proc_status_failed = TRUE;
		return -1;
	}
	return 0;
}

static int stat_get_rusage(struct process_stat *stat_r)
{
	struct rusage usage;

	if (getrusage(RUSAGE_SELF, &usage) < 0)
		return -1;
	stat_r->utime = timeval_to_usecs(&usage.ru_utime);
	stat_r->stime = timeval_to_usecs(&usage.ru_stime);
	stat_r->minor_faults = usage.ru_minflt;
	stat_r->major_faults = usage.ru_majflt;
	stat_r->vol_cs = usage.ru_nvcsw;
	stat_r->invol_cs = usage.ru_nivcsw;
	return 0;
}

static int parse_stat_file(struct process_stat *stat_r, struct event *event)
{
	int fd = -1;
	char buf[1024];
	unsigned int i;
	const char *const *tmp;
	struct {
		uint64_t *value;
		unsigned int idx;
	} fields[] = {
		{ &stat_r->minor_faults, 9 },
		{ &stat_r->major_faults, 11 },
		{ &stat_r->utime, 13 },
		{ &stat_r->stime, 14 },
		{ &stat_r->vsz, 22 },
		{ &stat_r->rss, 23 },
	};
	if (!stat_r->proc_stat_failed)
		fd = open_fd(PROC_STAT_PATH, event);
	if (fd == -1) {
		stat_r->proc_stat_failed = TRUE;
		/* vsz and rss are not provided by getrusage(), setting to undefined */
		stat_r->vsz = stat_undefined;
		stat_r->rss = stat_undefined;
		if (stat_r->rusage_failed)
			return -1;
		if (stat_get_rusage(stat_r) < 0) {
			e_error(event, "getrusage() failed: %m");
			stat_r->rusage_failed = TRUE;
			return -1;
		}
		return 0;
	}
	if (read_file(fd, PROC_STAT_PATH, buf, sizeof(buf), event) < 0) {
		stat_r->proc_stat_failed = TRUE;
		return -1;
	}
	tmp = t_strsplit(buf, " ");
	unsigned int tmp_count = str_array_length(tmp);

	for (i = 0; i < N_ELEMENTS(fields); i++) {
		if (fields[i].idx >= tmp_count ||
		    str_to_uint64(tmp[fields[i].idx], fields[i].value) < 0)
			*fields[i].value = stat_undefined;
	}
	/* rss is provided in pages, convert to bytes */
	stat_r->rss *= sysconf(_SC_PAGESIZE);
	return 0;
}

static int parse_all_stats(struct process_stat *stat_r, struct event *event)
{
	bool has_fields = FALSE;

	if (parse_stat_file(stat_r, event) == 0)
		has_fields = TRUE;
	if (parse_proc_io(stat_r, event) == 0)
		has_fields = TRUE;
	if ((!stat_r->proc_stat_failed || stat_r->rusage_failed) &&
	    parse_proc_status(stat_r, event) == 0)
		has_fields = TRUE;

	if (has_fields)
		return 0;
	return -1;
}

void process_stat_read_start(struct process_stat *stat_r, struct event *event)
{
	i_zero(stat_r);
	(void)parse_all_stats(stat_r, event);
}

void process_stat_read_finish(struct process_stat *stat, struct event *event)
{
	unsigned int i;
	struct process_stat new_stat;
	i_zero(&new_stat);
	new_stat.proc_io_failed = stat->proc_io_failed;
	new_stat.proc_status_failed = stat->proc_status_failed;
	new_stat.proc_stat_failed = stat->proc_stat_failed;
	new_stat.rusage_failed = stat->rusage_failed;
	if (parse_all_stats(&new_stat, event) < 0) {
		i_zero(stat);
		return;
	}
	stat->vsz = new_stat.vsz == stat_undefined ? 0 : new_stat.vsz;
	stat->rss = new_stat.rss == stat_undefined ? 0 : new_stat.rss;

	unsigned int cumulative_field_offsets[] = {
		offsetof(struct process_stat, utime),
		offsetof(struct process_stat, stime),
		offsetof(struct process_stat, minor_faults),
		offsetof(struct process_stat, major_faults),
		offsetof(struct process_stat, vol_cs),
		offsetof(struct process_stat, invol_cs),
		offsetof(struct process_stat, rchar),
		offsetof(struct process_stat, wchar),
		offsetof(struct process_stat, syscr),
		offsetof(struct process_stat, syscw),
	};
	for (i = 0; i < N_ELEMENTS(cumulative_field_offsets); i++) {
		uint64_t *old_value = PTR_OFFSET(stat, cumulative_field_offsets[i]);
		uint64_t *new_value = PTR_OFFSET(&new_stat, cumulative_field_offsets[i]);
		if (*old_value == stat_undefined || *new_value == stat_undefined)
			*old_value = 0;
		else
			*old_value = *new_value > *old_value ?
				(*new_value - *old_value) : 0;
	}
}
