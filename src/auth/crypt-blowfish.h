/*
 * Written by Solar Designer <solar at openwall.com> in 2000-2011.
 * No copyright is claimed, and the software is hereby placed in the public
 * domain.  In case this attempt to disclaim copyright and place the software
 * in the public domain is deemed null and void, then the software is
 * Copyright (c) 2000-2011 Solar Designer and it is hereby released to the
 * general public under the following terms:
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * There's ABSOLUTELY NO WARRANTY, express or implied.
 *
 * See crypt_blowfish.c for more information.
 *
 * 2017-10-10 - Adapted for dovecot code by Aki Tuomi <aki.tuomi@dovecot.fi>
 */

#ifndef CRYPT_BLOWFISH_H
#define CRYPT_BLOWFISH_H

extern int crypt_output_magic(const char *setting, char *output, size_t size);
extern char *crypt_blowfish_rn(const char *key, const char *setting,
	char *output, size_t size);
extern char *crypt_gensalt_blowfish_rn(const char *prefix,
	unsigned long count,
	const char *input, size_t size, char *output, size_t output_size);

#endif
