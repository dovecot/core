/* Copyright (c) 2009-2010 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "ioloop.h"
#include "network.h"
#include "crc32.h"
#include "anvil-client.h"
#include "auth-request.h"
#include "auth-penalty.h"

#include <stdio.h>

struct auth_penalty_request {
	struct auth_request *auth_request;
	auth_penalty_callback_t *callback;
};

struct auth_penalty {
	struct anvil_client *client;

	unsigned int disabled:1;
};

struct auth_penalty *auth_penalty_init(const char *path)
{
	struct auth_penalty *penalty;

	penalty = i_new(struct auth_penalty, 1);
	penalty->client = anvil_client_init(path, NULL,
					    ANVIL_CLIENT_FLAG_HIDE_ENOENT);
	if (anvil_client_connect(penalty->client, TRUE) < 0)
		penalty->disabled = TRUE;
	else {
		anvil_client_cmd(penalty->client, t_strdup_printf(
			"PENALTY-SET-EXPIRE-SECS\t%u", AUTH_PENALTY_TIMEOUT));
	}
	return penalty;
}

void auth_penalty_deinit(struct auth_penalty **_penalty)
{
	struct auth_penalty *penalty = *_penalty;

	*_penalty = NULL;
	anvil_client_deinit(&penalty->client);
	i_free(penalty);
}

unsigned int auth_penalty_to_secs(unsigned int penalty)
{
	unsigned int i, secs = AUTH_PENALTY_INIT_SECS;

	for (i = 0; i < penalty; i++)
		secs *= 2;
	return secs < AUTH_PENALTY_MAX_SECS ? secs : AUTH_PENALTY_MAX_SECS;
}

static void auth_penalty_anvil_callback(const char *reply, void *context)
{
	struct auth_penalty_request *request = context;
	unsigned int penalty = 0;
	unsigned long last_penalty = 0;
	unsigned int secs, drop_penalty;

	if (reply == NULL) {
		/* internal failure */
	} else if (sscanf(reply, "%u %lu", &penalty, &last_penalty) != 2) {
		i_error("Invalid PENALTY-GET reply: %s", reply);
	} else {
		if ((time_t)last_penalty > ioloop_time) {
			/* time moved backwards? */
			last_penalty = ioloop_time;
		}

		/* update penalty. */
		drop_penalty = AUTH_PENALTY_MAX_PENALTY;
		while (penalty > 0) {
			secs = auth_penalty_to_secs(drop_penalty);
			if (ioloop_time - last_penalty < secs)
				break;
			drop_penalty--;
			penalty--;
		}
	}

	request->callback(penalty, request->auth_request);
}

void auth_penalty_lookup(struct auth_penalty *penalty,
			 struct auth_request *auth_request,
			 auth_penalty_callback_t *callback)
{
	struct auth_penalty_request *request;
	const char *ident;

	ident = net_ip2addr(&auth_request->remote_ip);
	if (penalty->disabled || ident == NULL) {
		callback(0, auth_request);
		return;
	}

	request = i_new(struct auth_penalty_request, 1);
	request->auth_request = auth_request;
	request->callback = callback;

	T_BEGIN {
		anvil_client_query(penalty->client,
				   t_strdup_printf("PENALTY-GET\t%s", ident),
				   auth_penalty_anvil_callback, request);
	} T_END;
}

static unsigned int
get_userpass_checksum(struct auth_request *auth_request)
{
	return auth_request->mech_password == NULL ? 0 :
		crc32_str_more(crc32_str(auth_request->mech_password),
			       auth_request->user);
}

void auth_penalty_update(struct auth_penalty *penalty,
			 struct auth_request *auth_request, unsigned int value)
{
	const char *ident;

	ident = net_ip2addr(&auth_request->remote_ip);
	if (penalty->disabled || ident == NULL)
		return;

	if (value > AUTH_PENALTY_MAX_PENALTY) {
		/* even if the actual value doesn't change, the last_change
		   timestamp does. */
		value = AUTH_PENALTY_MAX_PENALTY;
	}
	T_BEGIN {
		const char *cmd;
		unsigned int checksum;

		checksum = value == 0 ? 0 : get_userpass_checksum(auth_request);
		cmd = t_strdup_printf("PENALTY-INC\t%s\t%u\t%u",
				      ident, checksum, value);
		anvil_client_cmd(penalty->client, cmd);
	} T_END;
}
