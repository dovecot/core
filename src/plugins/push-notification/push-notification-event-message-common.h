/* Copyright (c) 2015-2018 Dovecot authors, see the included COPYING file */

#ifndef PUSH_NOTIFICATION_EVENT_MESSAGE_COMMON_H
#define PUSH_NOTIFICATION_EVENT_MESSAGE_COMMON_H

enum push_notification_event_message_flags {
	/* Header: From */
	PUSH_NOTIFICATION_MESSAGE_HDR_FROM = 0x01,
	/* Header: To */
	PUSH_NOTIFICATION_MESSAGE_HDR_TO = 0x02,
	/* Header: Subject */
	PUSH_NOTIFICATION_MESSAGE_HDR_SUBJECT = 0x04,
	/* Header: Date */
	PUSH_NOTIFICATION_MESSAGE_HDR_DATE = 0x08,
	/* Body: Snippet */
	PUSH_NOTIFICATION_MESSAGE_BODY_SNIPPET = 0x10,
	/* Meta: Flags */
	PUSH_NOTIFICATION_MESSAGE_FLAGS = 0x20,
	/* Meta: Keywords */
	PUSH_NOTIFICATION_MESSAGE_KEYWORDS = 0x40,
	/* Header: Message-ID */
	PUSH_NOTIFICATION_MESSAGE_HDR_MESSAGE_ID = 0x80,
};

struct push_notification_message_ext {
	const char *from_address, *from_display_name_utf8;
	const char *to_address, *to_display_name_utf8;
	const char *subject_utf8;
};

void push_notification_message_fill(
	struct mail *mail, pool_t pool,
	enum push_notification_event_message_flags event_flags,
	const char **from, const char **to, const char **subject, time_t *date,
	int *date_tz, const char **message_id, enum mail_flags *flags,
	bool *flags_set, const char *const **keywords, const char **snippet,
	struct push_notification_message_ext *ext);

#endif

