#ifndef __AUTH_MECH_DESC_H
#define __AUTH_MECH_DESC_H

struct auth_mech_desc {
	enum auth_mech mech;
	const char *name;
	int plaintext;
	int advertise;
};

static struct auth_mech_desc auth_mech_desc[AUTH_MECH_COUNT] = {
	{ AUTH_MECH_PLAIN,		"PLAIN",	TRUE, FALSE },
	{ AUTH_MECH_DIGEST_MD5,		"DIGEST-MD5",	FALSE, TRUE },
	{ AUTH_MECH_ANONYMOUS,		"ANONYMOUS",	FALSE, TRUE }
};

#endif
