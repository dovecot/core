/* Copyright (C) 2003 Timo Sirainen */

#include "common.h"
#include "mech.h"

#ifdef USE_CYRUS_SASL2

#include <stdlib.h>
#include <sasl/sasl.h>

#include "auth-mech-desc.h"

struct cyrus_auth_request {
	struct auth_request auth_request;

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

static int
cyrus_sasl_auth_continue(struct login_connection *conn,
			 struct auth_request *auth_request,
			 struct auth_login_request_continue *request,
			 const unsigned char *data, mech_callback_t *callback)
{
	struct cyrus_auth_request *cyrus_request =
		(struct cyrus_auth_request *)auth_request;
	struct auth_login_reply reply;
	const char *serverout;
	unsigned int serveroutlen;
	int ret;

	ret = sasl_server_step(cyrus_request->conn, data, request->data_size,
			       &serverout, &serveroutlen);

	mech_init_login_reply(&reply);
	reply.id = request->id;

	if (ret == SASL_CONTINUE) {
		reply.result = AUTH_LOGIN_RESULT_CONTINUE;
		reply.data_size = serveroutlen;
	} else if (ret == SASL_OK) {
		/* success */
		reply.result = AUTH_LOGIN_RESULT_SUCCESS;
		cyrus_request->success = TRUE;

		serverout = mech_auth_success(&reply, auth_request,
					      serverout, serveroutlen);
	} else {
		/* failure */
		reply.result = AUTH_LOGIN_RESULT_FAILURE;
	}

	callback(&reply, serverout, conn);
	return reply.result != AUTH_LOGIN_RESULT_FAILURE;
}

#if 0
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
#endif

static void cyrus_sasl_auth_free(struct auth_request *auth_request)
{
	struct cyrus_auth_request *cyrus_request =
		(struct cyrus_auth_request *)auth_request;

	sasl_dispose(&cyrus_request->conn);
	pool_unref(auth_request->pool);
}

struct auth_request *mech_cyrus_sasl_new(struct login_connection *conn,
					 struct auth_login_request_new *request,
					 mech_callback_t *callback)
{
	static const char *propnames[] = {
		SASL_AUX_UIDNUM,
		SASL_AUX_GIDNUM,
		SASL_AUX_HOMEDIR,
		SASL_AUX_UNIXMBX,
		NULL
	};
	struct cyrus_auth_request *cyrus_request;
	struct auth_login_reply reply;
	const char *mech, *serverout;
	unsigned int serveroutlen;
	sasl_security_properties_t sec_props;
	sasl_conn_t *sasl_conn;
	pool_t pool;
	int ret;

	mech = auth_mech_to_str(request->mech);
	if (mech == NULL)
		i_fatal("Login asked for unknown mechanism %d", request->mech);

	/* create new SASL connection */
	ret = sasl_server_new("imap", NULL, NULL, NULL, NULL, NULL, 0,
			      &sasl_conn);
	if (ret != SASL_OK) {
		i_fatal("sasl_server_new() failed: %s",
			sasl_errstring(ret, NULL, NULL));
	}

	/* don't allow SASL security layer */
	memset(&sec_props, 0, sizeof(sec_props));
	sec_props.min_ssf = 0;
	sec_props.max_ssf = 1;

	if (sasl_setprop(sasl_conn, SASL_SEC_PROPS, &sec_props) != SASL_OK) {
		i_fatal("sasl_setprop(SASL_SEC_PROPS) failed: %s",
			sasl_errstring(ret, NULL, NULL));
	}

	ret = sasl_auxprop_request(sasl_conn, propnames);
	if (ret != SASL_OK) {
		i_fatal("sasl_auxprop_request() failed: %s",
			sasl_errstring(ret, NULL, NULL));
	}

	/* initialize reply */
	mech_init_login_reply(&reply);
	reply.id = request->id;
	reply.reply_idx = 0;

	/* start the exchange */
	ret = sasl_server_start(sasl_conn, mech, NULL, 0,
				&serverout, &serveroutlen);
	if (ret != SASL_CONTINUE) {
		reply.result = AUTH_LOGIN_RESULT_FAILURE;
		sasl_dispose(&sasl_conn);

		callback(&reply, NULL, conn);
		return NULL;
	}

	pool = pool_alloconly_create("cyrus_sasl_auth_request", 256);
	cyrus_request = p_new(pool, struct cyrus_auth_request, 1);

	cyrus_request->auth_request.pool = pool;
	cyrus_request->auth_request.auth_continue =
		cyrus_sasl_auth_continue;
	cyrus_request->auth_request.auth_free =
		cyrus_sasl_auth_free;

	reply.result = AUTH_LOGIN_RESULT_CONTINUE;

	reply.data_size = serveroutlen;
	callback(&reply, serverout, conn);

	return &cyrus_request->auth_request;
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

void mech_cyrus_sasl_init_lib(void)
{
	int ret;

	ret = sasl_server_init(sasl_callbacks, "dovecot-auth");
	if (ret != SASL_OK) {
		i_fatal("sasl_server_init() failed: %s",
			sasl_errstring(ret, NULL, NULL));
	}
}

#endif
