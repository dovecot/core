/* Copyright (c) 2008-2010 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "str.h"
#include "imap-utf7.h"

#include <stdio.h>

int main(int argc ATTR_UNUSED, const char *argv[])
{
	string_t *dest;
	bool reverse = FALSE;
	int ret;

	lib_init();

	if (argv[1] != NULL && strcmp(argv[1], "-r") == 0) {
		reverse = TRUE;
		argv++;
	}

	if (argv[1] == NULL) {
		fprintf(stderr, "Usage: %s [-r] <string>\n", argv[0]);
		return 1;
	}

	dest = t_str_new(256);
	ret = reverse ?
		imap_utf8_to_utf7(argv[1], dest) :
		imap_utf7_to_utf8(argv[1], dest);
	if (ret < 0) {
		fprintf(stderr, "Invalid input\n");
		return 1;
	}
	printf("%s\n", str_c(dest));
	return 0;
}
