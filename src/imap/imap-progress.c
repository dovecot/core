/* Copyright (c) 2025 Dovecot authors, see the included COPYING file */

#include "imap-common.h"
#include "str.h"
#include "time-util.h"
#include "imap-quote.h"
#include "imap-progress.h"

const char *
imap_progress_line(const struct mail_storage_progress_details *dtl,
		   const char *tag)
{
	const char *verb = dtl->verb;
	unsigned int total = dtl->total;
	unsigned int processed = dtl->processed;

	if (verb == NULL || *verb == '\0')
		verb = "Processed";

	if (total > 0 && processed >= total)
		processed = total - 1;

	/* The "]" character is totally legit in command tags, but it is
	   problematic inside IMAP resp-text-code(s), which are terminated
	   with "]". If the caracter appears inside the tag, we avoid
	   emitting the tag and replace it with NIL. */
	bool has_tag = tag != NULL && *tag != '\0' && strchr(tag, ']') == NULL;

	string_t *str = t_str_new(128);
	str_append(str, "* OK [INPROGRESS");
	if (has_tag || processed > 0 || total > 0) {
		str_append(str, " (");
		if (has_tag)
			imap_append_quoted(str, tag, FALSE);
		else
			str_append(str, "NIL");

		if (processed > 0 || total > 0)
			str_printfa(str, " %u", processed);
		else
			str_append(str, " NIL");

		if (total > 0)
			str_printfa(str, " %u", total);
		else
			str_append(str, " NIL");

		str_append_c(str, ')');
	}
	str_append(str, "] ");

	if (total > 0) {
		float percentage = processed * 100.0 / total;
		str_printfa(str, "%s %d%% of the mailbox", verb, (int)percentage);

		long long elapsed_ms = timeval_diff_msecs(&dtl->now,
							  &dtl->start_time);
		if (percentage > 0 && elapsed_ms > 0) {
			int eta_secs = elapsed_ms * (100 - percentage) /
					    (1000 * percentage);

			str_printfa(str, ", ETA %d:%02d",
				    eta_secs / 60, eta_secs % 60);
		}
	} else if (processed > 0)
		str_printfa(str, "%s %u item(s)", verb, processed);
	else
		str_append(str, "Hang in there..");

	return str_c(str);
}
