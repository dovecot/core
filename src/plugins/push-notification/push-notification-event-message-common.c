/* Copyright (c) 2015-2019 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "str.h"
#include "message-address.h"
#include "message-header-decode.h"
#include "mail-storage.h"
#include "push-notification-event-message-common.h"

static void decode_address_header(pool_t pool, const char *hdr,
				  const char **address_r, const char **name_r)
{
	struct message_address *addr;

	if (hdr == NULL)
		return;

	addr = message_address_parse(pool_datastack_create(),
		(const unsigned char *)hdr, strlen(hdr), 1, 0);
	if (addr->domain[0] != '\0')
		*address_r = p_strdup_printf(pool, "%s@%s", addr->mailbox,
					     addr->domain);
	else if (addr->mailbox[0] != '\0')
		*address_r = p_strdup(pool, addr->mailbox);

	if (addr->name != NULL) {
		string_t *name_utf8 = t_str_new(128);

		message_header_decode_utf8((const unsigned char *)addr->name,
					   strlen(addr->name), name_utf8, NULL);
		*name_r = p_strdup(pool, str_c(name_utf8));
	}
}

void push_notification_message_fill(struct mail *mail, pool_t pool,
				    enum push_notification_event_message_flags event_flags,
				    const char **from, const char **to,
				    const char **subject,
				    time_t *date, int *date_tz,
				    const char **message_id,
				    enum mail_flags *flags, bool *flags_set,
				    const char *const **keywords,
				    const char **snippet,
				    struct push_notification_message_ext *ext)
{
	const char *value;
	time_t tmp_date;
	int tmp_tz;

	if ((*from == NULL) &&
	    (event_flags & PUSH_NOTIFICATION_MESSAGE_HDR_FROM) != 0 &&
	    (mail_get_first_header(mail, "From", &value) >= 0)) {
		*from = p_strdup(pool, value);
		decode_address_header(pool, value, &ext->from_address,
				      &ext->from_display_name_utf8);
	}

	if ((*to == NULL) &&
	    (event_flags & PUSH_NOTIFICATION_MESSAGE_HDR_TO) != 0 &&
	    (mail_get_first_header(mail, "To", &value) >= 0)) {
		*to = p_strdup(pool, value);
		decode_address_header(pool, value, &ext->to_address,
				      &ext->to_display_name_utf8);
	}

	if ((*subject == NULL) &&
	    (event_flags & PUSH_NOTIFICATION_MESSAGE_HDR_SUBJECT) != 0 &&
	    (mail_get_first_header(mail, "Subject", &value) >= 0)) {
		string_t *subject_utf8 = t_str_new(128);

		*subject = p_strdup(pool, value);
		if (value != NULL) {
			message_header_decode_utf8((const unsigned char *)value,
						   strlen(value), subject_utf8, NULL);
			ext->subject_utf8 = p_strdup(pool, str_c(subject_utf8));
		}
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
		*keywords = p_strarray_dup(pool, mail_get_keywords(mail));
	}

	if ((*snippet == NULL) &&
	    (event_flags & PUSH_NOTIFICATION_MESSAGE_BODY_SNIPPET) != 0 &&
	    (mail_get_special(mail, MAIL_FETCH_BODY_SNIPPET, &value) >= 0)) {
		/* [0] contains the snippet algorithm, skip over it */
		i_assert(value[0] != '\0');
		*snippet = p_strdup(pool, value + 1);
	}
}
