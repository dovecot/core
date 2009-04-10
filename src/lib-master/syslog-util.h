#ifndef SYSLOG_UTIL_H
#define SYSLOG_UTIL_H

struct syslog_facility_list {
	const char *name;
	int facility;
};

extern struct syslog_facility_list syslog_facilities[];

/* Returns TRUE if found. */
bool syslog_facility_find(const char *name, int *facility_r);

#endif
