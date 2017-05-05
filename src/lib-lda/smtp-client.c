/* Copyright (c) 2006-2017 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "lda-settings.h"
#include "smtp-submit.h"
#include "smtp-client.h"

struct smtp_client {
	struct smtp_submit *submit;
};

struct smtp_client *
smtp_client_init(const struct lda_settings *set, const char *return_path)
{
	struct smtp_submit_settings smtp_set;
	struct smtp_client *client;

        i_zero(&smtp_set);
        smtp_set.hostname = set->hostname;
        smtp_set.submission_host = set->submission_host;
        smtp_set.sendmail_path = set->sendmail_path;

	client = i_new(struct smtp_client, 1);
	client->submit = smtp_submit_init(&smtp_set, return_path);
	return client;
}

void smtp_client_add_rcpt(struct smtp_client *client, const char *address)
{
	smtp_submit_add_rcpt(client->submit, address);
}

struct ostream *smtp_client_send(struct smtp_client *client)
{
	return smtp_submit_send(client->submit);
}

void smtp_client_abort(struct smtp_client **_client)
{
	struct smtp_client *client = *_client;

	*_client = NULL;

	smtp_submit_abort(&client->submit);
	i_free(client);
}

int smtp_client_deinit(struct smtp_client *client, const char **error_r)
{
	return smtp_client_deinit_timeout(client, 0, error_r);
}

int smtp_client_deinit_timeout(struct smtp_client *client,
			       unsigned int timeout_secs, const char **error_r)
{
	int  ret;

	ret = smtp_submit_deinit_timeout(client->submit, timeout_secs, error_r);
	i_free(client);
	return ret;
}
