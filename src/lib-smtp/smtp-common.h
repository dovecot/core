#ifndef SMTP_COMMON_H
#define SMTP_COMMON_H

/* SMTP capabilities */

enum smtp_capability {
	SMTP_CAPABILITY_AUTH                = 0x0001,
	SMTP_CAPABILITY_STARTTLS            = 0x0002,
	SMTP_CAPABILITY_PIPELINING          = 0x0004,
	SMTP_CAPABILITY_SIZE                = 0x0008,
	SMTP_CAPABILITY_ENHANCEDSTATUSCODES = 0x0010,
	SMTP_CAPABILITY_8BITMIME            = 0x0020,
	SMTP_CAPABILITY_CHUNKING            = 0x0040,
	SMTP_CAPABILITY_BINARYMIME          = 0x0080,
	SMTP_CAPABILITY_BURL                = 0x0100,
	SMTP_CAPABILITY_DSN                 = 0x0200,
	SMTP_CAPABILITY_VRFY                = 0x0400,
	SMTP_CAPABILITY_ETRN                = 0x0800,
	SMTP_CAPABILITY_XCLIENT             = 0x1000
};
struct smtp_capability_name {
	const char *name;
	enum smtp_capability capability;
};
extern const struct smtp_capability_name smtp_capability_names[];

#endif
