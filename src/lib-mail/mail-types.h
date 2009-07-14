#ifndef MAIL_TYPES_H
#define MAIL_TYPES_H

#define MAIL_GUID_128_SIZE 16

enum mail_flags {
	MAIL_ANSWERED	= 0x01,
	MAIL_FLAGGED	= 0x02,
	MAIL_DELETED	= 0x04,
	MAIL_SEEN	= 0x08,
	MAIL_DRAFT	= 0x10,
	MAIL_RECENT	= 0x20,

	MAIL_FLAGS_MASK = 0x3f,
	MAIL_FLAGS_NONRECENT = (MAIL_FLAGS_MASK ^ MAIL_RECENT)
};

enum modify_type {
	MODIFY_ADD,
	MODIFY_REMOVE,
	MODIFY_REPLACE
};

ARRAY_DEFINE_TYPE(keywords, const char *);
ARRAY_DEFINE_TYPE(keyword_indexes, unsigned int);

#endif
