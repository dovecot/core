#ifndef PROCESS_STAT_H
#define PROCESS_STAT_H

struct process_stat {
	uint64_t utime;
	uint64_t stime;
	uint64_t minor_faults;
	uint64_t major_faults;
	uint64_t vol_cs;
	uint64_t invol_cs;
	uint64_t rss;
	uint64_t vsz;
	uint64_t rchar;
	uint64_t wchar;
	uint64_t syscr;
	uint64_t syscw;
	bool proc_io_failed:1;
	bool rusage_failed:1;
	bool proc_stat_failed:1;
	bool proc_status_failed:1;
};

void process_stat_read_start(struct process_stat *stat_r, struct event *event);
void process_stat_read_finish(struct process_stat *stat, struct event *event);

#endif
