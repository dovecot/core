#ifndef __MAIL_TYPES_H
#define __MAIL_TYPES_H

enum mail_flags {
	MAIL_ANSWERED	= 0x01,
	MAIL_FLAGGED	= 0x02,
	MAIL_DELETED	= 0x04,
	MAIL_SEEN	= 0x08,
	MAIL_DRAFT	= 0x10,
	MAIL_RECENT	= 0x20,

	MAIL_FLAGS_MASK = 0x3f
};

struct mail_full_flags {
	enum mail_flags flags;

	const char **custom_flags;
	unsigned int custom_flags_count;
};

enum modify_type {
	MODIFY_ADD,
	MODIFY_REMOVE,
	MODIFY_REPLACE
};

#endif
