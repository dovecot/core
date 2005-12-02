/* Copyright (C) 2005 Timo Sirainen */

#include "lib.h"
#include "syslog-util.h"
#include <syslog.h>

struct syslog_facility_list syslog_facilities[] = {
	{ "auth", LOG_AUTH },
	{ "authpriv", LOG_AUTHPRIV },
	{ "cron", LOG_CRON },
	{ "daemon", LOG_DAEMON },
	{ "ftp", LOG_FTP },
	{ "kern", LOG_KERN },
	{ "local0", LOG_LOCAL0 },
	{ "local1", LOG_LOCAL1 },
	{ "local2", LOG_LOCAL2 },
	{ "local3", LOG_LOCAL3 },
	{ "local4", LOG_LOCAL4 },
	{ "local5", LOG_LOCAL5 },
	{ "local6", LOG_LOCAL6 },
	{ "local7", LOG_LOCAL7 },
	{ "lpr", LOG_LPR },
	{ "mail", LOG_MAIL },
	{ "news", LOG_NEWS },
	{ "syslog", LOG_SYSLOG },
	{ "user", LOG_USER },
	{ "uucp", LOG_UUCP },

	{ NULL, 0 }
};

int syslog_facility_find(const char *name, int *facility_r)
{
	int i;

	for (i = 0; syslog_facilities[i].name != NULL; i++) {
		if (strcmp(syslog_facilities[i].name, name) == 0) {
			*facility_r = syslog_facilities[i].facility;
			return TRUE;
		}
	}
	return FALSE;
}
