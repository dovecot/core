/* Copyright (c) 2015-2019 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "mail-storage.h"
#include "push-notification-event-message-common.h"

void push_notification_message_fill(struct mail *mail, pool_t pool,
				    enum push_notification_event_message_flags event_flags,
				    const char **from, const char **to,
				    const char **subject,
				    time_t *date, int *date_tz,
				    const char **message_id,
				    enum mail_flags *flags, bool *flags_set,
				    const char *const **keywords,
				    const char **snippet)
{
	const char *value;
	time_t tmp_date;
	int tmp_tz;

	if ((*from == NULL) &&
	    (event_flags & PUSH_NOTIFICATION_MESSAGE_HDR_FROM) != 0 &&
	    (mail_get_first_header(mail, "From", &value) >= 0)) {
		*from = p_strdup(pool, value);
	}

	if ((*to == NULL) &&
	    (event_flags & PUSH_NOTIFICATION_MESSAGE_HDR_TO) != 0 &&
	    (mail_get_first_header(mail, "To", &value) >= 0)) {
		*to = p_strdup(pool, value);
	}

	if ((*subject == NULL) &&
	    (event_flags & PUSH_NOTIFICATION_MESSAGE_HDR_SUBJECT) != 0 &&
	    (mail_get_first_header(mail, "Subject", &value) >= 0)) {
		*subject = p_strdup(pool, value);
	}

	if ((*date == -1) &&
	    (event_flags & PUSH_NOTIFICATION_MESSAGE_HDR_DATE) != 0 &&
	    (mail_get_date(mail, &tmp_date, &tmp_tz) >= 0)) {
		*date = tmp_date;
		*date_tz = tmp_tz;
	}

	if ((*message_id == NULL) &&
	    (event_flags & PUSH_NOTIFICATION_MESSAGE_HDR_MESSAGE_ID) != 0 &&
	    (mail_get_first_header(mail, "Message-ID", &value) >= 0)) {
		*message_id = p_strdup(pool, value);
	}

	if (!*flags_set &&
	    (event_flags & PUSH_NOTIFICATION_MESSAGE_FLAGS) != 0) {
		*flags = mail_get_flags(mail);
		*flags_set = TRUE;
	}

	if ((*keywords == NULL) &&
	    (event_flags & PUSH_NOTIFICATION_MESSAGE_KEYWORDS) != 0) {
		const char *const *mail_kws = mail_get_keywords(mail);
		ARRAY_TYPE(const_string) kws;
		p_array_init(&kws, pool, 2);
		for (;*mail_kws != NULL; mail_kws++) {
			value = p_strdup(pool, *mail_kws);
			array_append(&kws, &value, 1);
		}
		array_append_zero(&kws);
		*keywords = array_idx(&kws, 0);
	}

	if ((*snippet == NULL) &&
	    (event_flags & PUSH_NOTIFICATION_MESSAGE_BODY_SNIPPET) != 0 &&
	    (mail_get_special(mail, MAIL_FETCH_BODY_SNIPPET, &value) >= 0)) {
		/* [0] contains the snippet algorithm, skip over it */
		i_assert(value[0] != '\0');
		*snippet = p_strdup(pool, value + 1);
	}
}
