/* Copyright (C) 2003 Timo Sirainen */

#include "common.h"
#include "auth.h"
#include "cookie.h"

#ifdef USE_CYRUS_SASL2

#include <stdlib.h>
#include <sasl/sasl.h>

#include "auth-mech-desc.h"

struct auth_context {
	sasl_conn_t *conn;
	int success;
};

static const char *auth_mech_to_str(enum auth_mech mech)
{
	int i;

	for (i = 0; i < AUTH_MECH_COUNT; i++) {
		if (auth_mech_desc[i].mech == mech)
			return auth_mech_desc[i].name;
	}

	return NULL;
}

static void auth_sasl_continue(struct cookie_data *cookie,
			       struct auth_continued_request_data *request,
			       const unsigned char *data,
			       auth_callback_t callback, void *context)
{
	struct auth_context *ctx = cookie->context;
	struct auth_reply_data reply;
	const char *serverout;
	unsigned int serveroutlen;
	int ret;

	ret = sasl_server_step(ctx->conn, data, request->data_size,
			       &serverout, &serveroutlen);

	memset(&reply, 0, sizeof(reply));
	reply.id = request->id;
	memcpy(reply.cookie, cookie->cookie, AUTH_COOKIE_SIZE);

	if (ret == SASL_CONTINUE) {
		reply.result = AUTH_RESULT_CONTINUE;
	} else if (ret == SASL_OK) {
		/* success */
		reply.result = AUTH_RESULT_SUCCESS;
		ctx->success = TRUE;
	} else {
		/* failure */
		reply.result = AUTH_RESULT_FAILURE;
		cookie_remove(cookie->cookie);
	}

	reply.data_size = serveroutlen;
        callback(&reply, serverout, context);
}

static int auth_sasl_fill_reply(struct cookie_data *cookie,
				struct auth_cookie_reply_data *reply)
{
	struct auth_context *ctx = cookie->context;
	const char *canon_user;
        const struct propval *prop;
	int ret;

	if (!ctx->success)
		return FALSE;

	/* get our username */
	ret = sasl_getprop(ctx->conn, SASL_USERNAME,
			   (const void **) &canon_user);
	if (ret != SASL_OK) {
		i_warning("sasl_getprop() failed: %s",
			  sasl_errstring(ret, NULL, NULL));
		return FALSE;
	}

	memset(reply, 0, sizeof(*reply));
	reply->success = TRUE;

	if (strocpy(reply->virtual_user, canon_user,
		    sizeof(reply->virtual_user)) < 0)
		i_panic("virtual_user overflow");

	/* get other properties */
	prop = prop_get(sasl_auxprop_getctx(ctx->conn));
	for (; prop != NULL && prop->name != NULL; prop++) {
		if (prop->nvalues == 0 || prop->values[0] == NULL)
			continue;

		if (strcasecmp(prop->name, SASL_AUX_UIDNUM) == 0)
			reply->uid = atoi(prop->values[0]);
		else if (strcasecmp(prop->name, SASL_AUX_GIDNUM) == 0)
			reply->gid = atoi(prop->values[0]);
		else if (strcasecmp(prop->name, SASL_AUX_HOMEDIR) == 0) {
			if (strocpy(reply->home, prop->values[0],
				    sizeof(reply->home)) < 0)
				i_panic("home overflow");
		} else if (strcasecmp(prop->name, SASL_AUX_UNIXMBX) == 0) {
			if (strocpy(reply->mail, prop->values[0],
				    sizeof(reply->mail)) < 0)
				i_panic("mail overflow");
		}
	}

	return TRUE;
}

static void auth_sasl_free(struct cookie_data *cookie)
{
	struct auth_context *ctx = cookie->context;

	sasl_dispose(&ctx->conn);
	i_free(ctx);
	i_free(cookie);
}

void auth_cyrus_sasl_init(unsigned int login_pid,
			  struct auth_init_request_data *request,
			  auth_callback_t callback, void *context)
{
	static const char *propnames[] = {
		SASL_AUX_UIDNUM,
		SASL_AUX_GIDNUM,
		SASL_AUX_HOMEDIR,
		SASL_AUX_UNIXMBX,
		NULL
	};
	struct cookie_data *cookie;
	struct auth_reply_data reply;
	struct auth_context *ctx;
	const char *mech, *serverout;
	unsigned int serveroutlen;
	sasl_security_properties_t sec_props;
	sasl_conn_t *conn;
	int ret;

	mech = auth_mech_to_str(request->mech);
	if (mech == NULL)
		i_fatal("Login asked for unknown mechanism %d", request->mech);

	/* create new SASL connection */
	ret = sasl_server_new("imap", NULL, NULL, NULL, NULL, NULL, 0, &conn);
	if (ret != SASL_OK) {
		i_fatal("sasl_server_new() failed: %s",
			sasl_errstring(ret, NULL, NULL));
	}

	/* don't allow SASL security layer */
	memset(&sec_props, 0, sizeof(sec_props));
	sec_props.min_ssf = 0;
	sec_props.max_ssf = 1;

	if (sasl_setprop(conn, SASL_SEC_PROPS, &sec_props) != SASL_OK) {
		i_fatal("sasl_setprop(SASL_SEC_PROPS) failed: %s",
			sasl_errstring(ret, NULL, NULL));
	}

	ret = sasl_auxprop_request(conn, propnames);
	if (ret != SASL_OK) {
		i_fatal("sasl_auxprop_request() failed: %s",
			sasl_errstring(ret, NULL, NULL));
	}

	/* initialize reply */
	memset(&reply, 0, sizeof(reply));
	reply.id = request->id;

	/* start the exchange */
	ret = sasl_server_start(conn, mech, NULL, 0, &serverout, &serveroutlen);
	if (ret != SASL_CONTINUE) {
		reply.result = AUTH_RESULT_FAILURE;
		serverout = NULL;
		serveroutlen = 0;
		sasl_dispose(&conn);
	} else {
		cookie = i_new(struct cookie_data, 1);
		cookie->login_pid = login_pid;
		cookie->auth_fill_reply = auth_sasl_fill_reply;
		cookie->auth_continue = auth_sasl_continue;
		cookie->free = auth_sasl_free;
		ctx = cookie->context = i_new(struct auth_context, 1);
		ctx->conn = conn;

		cookie_add(cookie);

		reply.result = AUTH_RESULT_CONTINUE;
		memcpy(reply.cookie, cookie->cookie, AUTH_COOKIE_SIZE);
	}

	reply.data_size = serveroutlen;
	callback(&reply, serverout, context);
}

static int sasl_log(void *context __attr_unused__,
		    int level, const char *message)
{
	switch (level) {
	case SASL_LOG_ERR:
		i_error("SASL authentication error: %s", message);
		break;
	case SASL_LOG_WARN:
		i_warning("SASL authentication warning: %s", message);
		break;
	case SASL_LOG_NOTE:
		/*i_info("SASL authentication info: %s", message);*/
		break;
	case SASL_LOG_FAIL:
		/*i_info("SASL authentication failure: %s", message);*/
		break;
	}

	return SASL_OK;
}

static const struct sasl_callback sasl_callbacks[] = {
	{ SASL_CB_LOG, &sasl_log, NULL },
	{ SASL_CB_LIST_END, NULL, NULL }
};

void auth_cyrus_sasl_init_lib(void)
{
	int ret;

	ret = sasl_server_init(sasl_callbacks, "imap-auth");
	if (ret != SASL_OK) {
		i_fatal("sasl_server_init() failed: %s",
			sasl_errstring(ret, NULL, NULL));
	}
}

#endif
