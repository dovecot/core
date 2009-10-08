/* Copyright (c) 2009 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "master-service.h"
#include "doveadm-mail.h"
#include "doveadm.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void usage(void)
{
	fprintf(stderr, "usage: doveadm\n");
	doveadm_mail_usage();
	exit(1);
}

int main(int argc, char *argv[])
{
	const char *cmd_name, *getopt_str;
	int c;

	master_service = master_service_init("doveadm",
					     MASTER_SERVICE_FLAG_STANDALONE,
					     argc, argv);
	doveadm_mail_init();

	/* "+" is GNU extension to stop at the first non-option.
	   others just accept -+ option. */
	getopt_str = t_strconcat("+", master_service_getopt_string(), NULL);
	while ((c = getopt(argc, argv, getopt_str)) > 0) {
		if (!master_service_parse_option(master_service, c, optarg))
			usage();
	}
	if (optind == argc)
		usage();

	cmd_name = argv[optind];
	argc -= optind;
	argv += optind;

	if (!doveadm_mail_try_run(cmd_name, argc, argv))
		usage();

	master_service_deinit(&master_service);
	doveadm_mail_deinit();
	return 0;
}
