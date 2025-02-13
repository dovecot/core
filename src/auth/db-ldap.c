/* Copyright (c) 2003-2018 Dovecot authors, see the included COPYING file */

#include "auth-common.h"

#if defined(BUILTIN_LDAP) || defined(PLUGIN_BUILD)

#include "safe-memset.h"
#include "net.h"
#include "ioloop.h"
#include "array.h"
#include "hash.h"
#include "aqueue.h"
#include "str.h"
#include "strescape.h"
#include "time-util.h"
#include "env-util.h"
#include "settings.h"
#include "ssl-settings.h"
#include "userdb.h"
#include "db-ldap.h"
#include "ldap-utils.h"

#include <unistd.h>

#define HAVE_LDAP_SASL
#ifdef HAVE_SASL_SASL_H
#  include <sasl/sasl.h>
#elif defined (HAVE_SASL_H)
#  include <sasl.h>
#else
#  undef HAVE_LDAP_SASL
#endif
#ifdef LDAP_OPT_X_TLS
#  define OPENLDAP_TLS_OPTIONS
#endif
#if !defined(SASL_VERSION_MAJOR) || SASL_VERSION_MAJOR < 2
#  undef HAVE_LDAP_SASL
#endif

#ifndef LDAP_SASL_QUIET
#  define LDAP_SASL_QUIET 0 /* Doesn't exist in Solaris LDAP */
#endif

/* Older versions may require calling ldap_result() twice */
#if LDAP_VENDOR_VERSION <= 20112
#  define OPENLDAP_ASYNC_WORKAROUND
#endif

/* Solaris LDAP library doesn't have LDAP_OPT_SUCCESS */
#ifndef LDAP_OPT_SUCCESS
#  define LDAP_OPT_SUCCESS LDAP_SUCCESS
#endif

#define DB_LDAP_REQUEST_MAX_ATTEMPT_COUNT 3
#define DB_LDAP_ATTR_DN "~dn"

static const char *LDAP_ESCAPE_CHARS = "*,\\#+<>;\"()= ";

struct db_ldap_result {
	int refcount;
	LDAPMessage *msg;
};

struct db_ldap_value {
	const char **values;
	bool used;
};

struct db_ldap_result_iterate_context {
	pool_t pool;

	struct ldap_request *ldap_request;
	const char *const *attr_next;
	const char *const *sensitive_attr_names;

	/* attribute name => value */
	HASH_TABLE(char *, struct db_ldap_value *) ldap_attrs;

	const char *val_1_arr[2];
	string_t *var, *debug;

	bool skip_null_values;
	LDAPMessage *ldap_msg;
	LDAP *ld;
};

struct db_ldap_sasl_bind_context {
	const char *authcid;
	const char *passwd;
	const char *realm;
	const char *authzid;
};

static struct ldap_connection *ldap_connections = NULL;

static int db_ldap_bind(struct ldap_connection *conn);
static void db_ldap_conn_close(struct ldap_connection *conn);
struct db_ldap_result_iterate_context *
db_ldap_result_iterate_init_full(struct ldap_connection *conn,
				 struct ldap_request_search *ldap_request,
				 LDAPMessage *res, bool skip_null_values);
static bool db_ldap_abort_requests(struct ldap_connection *conn,
				   unsigned int max_count,
				   unsigned int timeout_secs,
				   bool error, const char *reason);
static void db_ldap_request_free(struct ldap_request *request);

static int ldap_get_errno(struct ldap_connection *conn)
{
	int ret, err;

	ret = ldap_get_option(conn->ld, LDAP_OPT_ERROR_NUMBER, (void *) &err);
	if (ret != LDAP_SUCCESS) {
		e_error(conn->event, "Can't get error number: %s",
			ldap_err2string(ret));
		return LDAP_UNAVAILABLE;
	}

	return err;
}

const char *ldap_get_error(struct ldap_connection *conn)
{
	const char *ret;
	char *str = NULL;

	ret = ldap_err2string(ldap_get_errno(conn));

	ldap_get_option(conn->ld, LDAP_OPT_ERROR_STRING, (void *)&str);
	if (str != NULL) {
		ret = t_strconcat(ret, ", ", str, NULL);
		ldap_memfree(str);
	}
	ldap_set_option(conn->ld, LDAP_OPT_ERROR_STRING, NULL);
	return ret;
}

static void ldap_conn_reconnect(struct ldap_connection *conn)
{
	db_ldap_conn_close(conn);
	if (db_ldap_connect(conn) < 0)
		db_ldap_conn_close(conn);
}

static int ldap_handle_error(struct ldap_connection *conn)
{
	int err = ldap_get_errno(conn);

	switch (err) {
	case LDAP_SUCCESS:
		i_unreached();
	case LDAP_SIZELIMIT_EXCEEDED:
	case LDAP_TIMELIMIT_EXCEEDED:
	case LDAP_NO_SUCH_ATTRIBUTE:
	case LDAP_UNDEFINED_TYPE:
	case LDAP_INAPPROPRIATE_MATCHING:
	case LDAP_CONSTRAINT_VIOLATION:
	case LDAP_TYPE_OR_VALUE_EXISTS:
	case LDAP_INVALID_SYNTAX:
	case LDAP_NO_SUCH_OBJECT:
	case LDAP_ALIAS_PROBLEM:
	case LDAP_INVALID_DN_SYNTAX:
	case LDAP_IS_LEAF:
	case LDAP_ALIAS_DEREF_PROBLEM:
	case LDAP_FILTER_ERROR:
		/* invalid input */
		return -1;
	case LDAP_SERVER_DOWN:
	case LDAP_TIMEOUT:
	case LDAP_UNAVAILABLE:
	case LDAP_BUSY:
#ifdef LDAP_CONNECT_ERROR
	case LDAP_CONNECT_ERROR:
#endif
	case LDAP_LOCAL_ERROR:
	case LDAP_INVALID_CREDENTIALS:
	case LDAP_OPERATIONS_ERROR:
	default:
		/* connection problems */
		ldap_conn_reconnect(conn);
		return 0;
	}
}

static int db_ldap_request_bind(struct ldap_connection *conn,
				struct ldap_request *request)
{
	struct auth_request *arequest = request->auth_request;
	struct ldap_request_bind *brequest =
		container_of(request, struct ldap_request_bind, request);

	i_assert(request->type == LDAP_REQUEST_TYPE_BIND);
	i_assert(request->msgid == -1);
	i_assert(conn->conn_state == LDAP_CONN_STATE_BOUND_AUTH ||
		 conn->conn_state == LDAP_CONN_STATE_BOUND_DEFAULT);
	i_assert(conn->pending_count == 0);

	struct berval creds = {
		.bv_val = arequest->mech_password,
		.bv_len = strlen(arequest->mech_password)
	};

	int ret = ldap_sasl_bind(conn->ld, brequest->dn, LDAP_SASL_SIMPLE,
				 &creds, NULL, NULL, &request->msgid);
	if (ret != LDAP_SUCCESS) {
		e_error(authdb_event(arequest),
			"ldap_sasl_bind(%s) failed: %s",
			brequest->dn, ldap_get_error(conn));
		if (ldap_handle_error(conn) < 0) {
			/* broken request, remove it */
			return 0;
		}
		return -1;
	}
	conn->conn_state = LDAP_CONN_STATE_BINDING;
	return 1;
}

static int db_ldap_request_search(struct ldap_connection *conn,
				  struct ldap_request *request)
{
	struct ldap_request_search *srequest =
		container_of(request, struct ldap_request_search, request);

	i_assert(conn->conn_state == LDAP_CONN_STATE_BOUND_DEFAULT);
	i_assert(request->msgid == -1);

	ldap_search_ext(
		conn->ld, *srequest->base == '\0' ? NULL : srequest->base,
		conn->set->parsed_scope, srequest->filter, (char **)srequest->attributes,
		0, NULL, NULL, 0, 0, &request->msgid);
	if (request->msgid == -1) {
		e_error(authdb_event(request->auth_request),
			"ldap_search_ext(%s) parsing failed: %s",
			srequest->filter, ldap_get_error(conn));
		if (ldap_handle_error(conn) < 0) {
			/* broken request, remove it */
			return 0;
		}
		return -1;
	}
	return 1;
}

static bool db_ldap_request_queue_next(struct ldap_connection *conn)
{
	struct ldap_request *request;
	int ret = -1;

	/* connecting may call db_ldap_connect_finish(), which gets us back
	   here. so do the connection before checking the request queue. */
	if (db_ldap_connect(conn) < 0)
		return FALSE;

	if (conn->pending_count == aqueue_count(conn->request_queue)) {
		/* no non-pending requests */
		return FALSE;
	}
	if (conn->pending_count > DB_LDAP_MAX_PENDING_REQUESTS) {
		/* wait until server has replied to some requests */
		return FALSE;
	}

	request = array_idx_elem(&conn->request_array,
				 aqueue_idx(conn->request_queue,
					    conn->pending_count));

	if (conn->pending_count > 0 &&
	    request->type == LDAP_REQUEST_TYPE_BIND) {
		/* we can't do binds until all existing requests are finished */
		return FALSE;
	}

	switch (conn->conn_state) {
	case LDAP_CONN_STATE_DISCONNECTED:
	case LDAP_CONN_STATE_BINDING:
		/* wait until we're in bound state */
		return FALSE;
	case LDAP_CONN_STATE_BOUND_AUTH:
		if (request->type == LDAP_REQUEST_TYPE_BIND)
			break;

		/* bind to default dn first */
		i_assert(conn->pending_count == 0);
		(void)db_ldap_bind(conn);
		return FALSE;
	case LDAP_CONN_STATE_BOUND_DEFAULT:
		/* we can do anything in this state */
		break;
	}

	if (request->send_count >= DB_LDAP_REQUEST_MAX_ATTEMPT_COUNT) {
		/* Enough many times retried. Server just keeps disconnecting
		   whenever attempting to send the request. */
		ret = 0;
	} else {
		/* clear away any partial results saved before reconnecting */
		db_ldap_request_free(request);

		switch (request->type) {
		case LDAP_REQUEST_TYPE_BIND:
			ret = db_ldap_request_bind(conn, request);
			break;
		case LDAP_REQUEST_TYPE_SEARCH:
			ret = db_ldap_request_search(conn, request);
			break;
		}
	}

	if (ret > 0) {
		/* success */
		i_assert(request->msgid != -1);
		request->send_count++;
		conn->pending_count++;
		return TRUE;
	} else if (ret < 0) {
		/* disconnected */
		return FALSE;
	} else {
		/* broken request, remove from queue */
		aqueue_delete(conn->request_queue, conn->pending_count);
		request->callback(conn, request, NULL);
		return TRUE;
	}
}

static void
db_ldap_check_hanging(struct ldap_connection *conn)
{
	struct ldap_request *first_request;
	unsigned int count;
	time_t secs_diff;

	count = aqueue_count(conn->request_queue);
	if (count == 0)
		return;

	first_request = array_idx_elem(&conn->request_array,
				       aqueue_idx(conn->request_queue, 0));
	secs_diff = ioloop_time - first_request->create_time;
	if (secs_diff > DB_LDAP_REQUEST_LOST_TIMEOUT_SECS) {
		db_ldap_abort_requests(conn, UINT_MAX, 0, TRUE,
				       "LDAP connection appears to be hanging");
		ldap_conn_reconnect(conn);
	}
}

void db_ldap_request(struct ldap_connection *conn,
		     struct ldap_request *request)
{
	i_assert(request->auth_request != NULL);

	request->msgid = -1;
	request->create_time = ioloop_time;

	db_ldap_check_hanging(conn);

	aqueue_append(conn->request_queue, &request);
	(void)db_ldap_request_queue_next(conn);
}

static int db_ldap_connect_finish(struct ldap_connection *conn, int ret)
{
	if (ret == LDAP_SERVER_DOWN) {
		e_error(conn->event, "Can't connect to server: %s",
			conn->set->uris);
		return -1;
	}
	if (ret != LDAP_SUCCESS) {
		e_error(conn->event, "binding failed (dn %s): %s",
			*conn->set->auth_dn == '\0' ? "(none)" : conn->set->auth_dn,
			ldap_get_error(conn));
		return -1;
	}

	timeout_remove(&conn->to);
	conn->conn_state = LDAP_CONN_STATE_BOUND_DEFAULT;
	while (db_ldap_request_queue_next(conn))
		;
	return 0;
}

static void db_ldap_default_bind_finished(struct ldap_connection *conn,
					  struct db_ldap_result *res)
{
	i_assert(conn->pending_count == 0);
	conn->default_bind_msgid = -1;

	int result;
	int ret = ldap_parse_result(conn->ld, res->msg, &result,
				    NULL, NULL, NULL, NULL, FALSE);
	/* ldap_parse_result() itself can fail client-side.
	   In that case ret already contains our error code... */
	if (ret == LDAP_SUCCESS) {
		/* ... on the other hand, the result of a successful parsing
		   can be itself a server-side error, whose error-code is
		   stored in result. Pass it into ret and handle it as well. */
		ret = result;
	}
	if (db_ldap_connect_finish(conn, ret) < 0) {
		/* lost connection, close it */
		db_ldap_conn_close(conn);
	}
}

static bool db_ldap_abort_requests(struct ldap_connection *conn,
				   unsigned int max_count,
				   unsigned int timeout_secs,
				   bool error, const char *reason)
{
	struct ldap_request *request;
	time_t diff;
	bool aborts = FALSE;

	while (aqueue_count(conn->request_queue) > 0 && max_count > 0) {
		request = array_idx_elem(&conn->request_array,
					 aqueue_idx(conn->request_queue, 0));

		diff = ioloop_time - request->create_time;
		if (diff < (time_t)timeout_secs)
			break;

		/* timed out, abort */
		aqueue_delete_tail(conn->request_queue);

		if (request->msgid != -1) {
			i_assert(conn->pending_count > 0);
			conn->pending_count--;
		}
		if (error) {
			e_error(authdb_event(request->auth_request),
				"%s", reason);
		} else {
			e_info(authdb_event(request->auth_request),
			       "%s", reason);
		}
		request->callback(conn, request, NULL);
		max_count--;
		aborts = TRUE;
	}
	return aborts;
}

static struct ldap_request *
db_ldap_find_request(struct ldap_connection *conn, int msgid,
		     unsigned int *idx_r)
{
	struct ldap_request *const *requests, *request = NULL;
	unsigned int i, count;

	count = aqueue_count(conn->request_queue);
	if (count == 0)
		return NULL;

	requests = array_front(&conn->request_array);
	for (i = 0; i < count; i++) {
		request = requests[aqueue_idx(conn->request_queue, i)];
		if (request->msgid == msgid) {
			*idx_r = i;
			return request;
		}
		if (request->msgid == -1)
			break;
	}
	return NULL;
}


static int db_ldap_search_save_result(struct ldap_request_search *request,
				      struct db_ldap_result *res)
{
	struct ldap_request_named_result *named_res;

	if (!array_is_created(&request->named_results)) {
		if (request->result != NULL)
			return -1;
		request->result = res;
	} else {
		named_res = array_idx_modifiable(&request->named_results,
						 request->name_idx);
		if (named_res->result != NULL)
			return -1;
		named_res->result = res;
	}
	res->refcount++;
	return 0;
}

static bool
db_ldap_handle_request_result(struct ldap_connection *conn,
			      struct ldap_request *request, unsigned int idx,
			      struct db_ldap_result *res)
{
	struct ldap_request_search *srequest =
		container_of(request, struct ldap_request_search, request);
	const struct ldap_request_named_result *named_res;
	int ret;
	bool final_result;

	i_assert(conn->pending_count > 0);

	if (request->type == LDAP_REQUEST_TYPE_BIND) {
		i_assert(conn->conn_state == LDAP_CONN_STATE_BINDING);
		i_assert(conn->pending_count == 1);
		conn->conn_state = LDAP_CONN_STATE_BOUND_AUTH;
	} else {
		switch (ldap_msgtype(res->msg)) {
		case LDAP_RES_SEARCH_ENTRY:
		case LDAP_RES_SEARCH_RESULT:
			break;
		case LDAP_RES_SEARCH_REFERENCE:
			/* we're going to ignore this */
			return FALSE;
		default:
			e_error(conn->event, "Reply with unexpected type %d",
				ldap_msgtype(res->msg));
			return TRUE;
		}
	}
	if (ldap_msgtype(res->msg) == LDAP_RES_SEARCH_ENTRY) {
		ret = LDAP_SUCCESS;
		final_result = FALSE;
	} else {
		final_result = TRUE;
		int result;
		ret = ldap_parse_result(conn->ld, res->msg, &result,
					NULL, NULL, NULL, NULL, FALSE);
		if (ret == LDAP_SUCCESS)
			ret = result;
	}
	/* LDAP_NO_SUCH_OBJECT is returned for nonexistent base */
	if (ret != LDAP_SUCCESS && ret != LDAP_NO_SUCH_OBJECT &&
	    request->type == LDAP_REQUEST_TYPE_SEARCH) {
		/* handle search failures here */
		if (!array_is_created(&srequest->named_results)) {
			e_error(authdb_event(request->auth_request),
				"ldap_search_ext(base=%s filter=%s) failed: %s",
				srequest->base, srequest->filter,
				ldap_err2string(ret));
		} else {
			named_res = array_idx(&srequest->named_results,
					      srequest->name_idx);
			e_error(authdb_event(request->auth_request),
				"ldap_search_ext(base=%s) failed: %s",
				named_res->dn, ldap_err2string(ret));
		}
		res = NULL;
	}
	if (ret == LDAP_SUCCESS && srequest != NULL && !srequest->multi_entry) {
		if (!final_result) {
			if (db_ldap_search_save_result(srequest, res) < 0) {
				e_error(authdb_event(request->auth_request),
					"LDAP search returned multiple entries");
				res = NULL;
			} else {
				/* wait for finish */
				return FALSE;
			}
		}
	}
	if (res == NULL && !final_result) {
		/* wait for the final reply */
		request->failed = TRUE;
		return TRUE;
	}
	if (request->failed)
		res = NULL;
	if (final_result) {
		conn->pending_count--;
		aqueue_delete(conn->request_queue, idx);
	}

	T_BEGIN {
		if (res != NULL && srequest != NULL && srequest->result != NULL)
			request->callback(conn, request, srequest->result->msg);

		request->callback(conn, request, res == NULL ? NULL : res->msg);
	} T_END;

	if (idx > 0) {
		/* see if there are timed out requests */
		if (db_ldap_abort_requests(conn, idx,
					   DB_LDAP_REQUEST_LOST_TIMEOUT_SECS,
					   TRUE, "Request lost"))
			ldap_conn_reconnect(conn);
	}
	return TRUE;
}

static void db_ldap_result_unref(struct db_ldap_result **_res)
{
	struct db_ldap_result *res = *_res;

	*_res = NULL;
	i_assert(res->refcount > 0);
	if (--res->refcount == 0) {
		ldap_msgfree(res->msg);
		i_free(res);
	}
}

static void
db_ldap_request_free(struct ldap_request *request)
{
	if (request->type == LDAP_REQUEST_TYPE_SEARCH) {
		struct ldap_request_search *srequest =
			container_of(request, struct ldap_request_search, request);
		struct ldap_request_named_result *named_res;

		if (srequest->result != NULL)
			db_ldap_result_unref(&srequest->result);

		if (array_is_created(&srequest->named_results)) {
			array_foreach_modifiable(&srequest->named_results, named_res) {
				if (named_res->result != NULL)
					db_ldap_result_unref(&named_res->result);
			}
			array_free(&srequest->named_results);
			srequest->name_idx = 0;
		}
	}
}

static void
db_ldap_handle_result(struct ldap_connection *conn, struct db_ldap_result *res)
{
	struct auth_request *auth_request;
	struct ldap_request *request;
	unsigned int idx;
	int msgid;

	msgid = ldap_msgid(res->msg);
	if (msgid == conn->default_bind_msgid) {
		db_ldap_default_bind_finished(conn, res);
		return;
	}

	request = db_ldap_find_request(conn, msgid, &idx);
	if (request == NULL) {
		e_error(conn->event, "Reply with unknown msgid %d", msgid);
		ldap_conn_reconnect(conn);
		return;
	}
	/* request is allocated from auth_request's pool */
	auth_request = request->auth_request;
	auth_request_ref(auth_request);
	if (db_ldap_handle_request_result(conn, request, idx, res))
		db_ldap_request_free(request);
	auth_request_unref(&auth_request);
}

static void ldap_input(struct ldap_connection *conn)
{
	struct timeval timeout;
	struct db_ldap_result *res;
	LDAPMessage *msg;
	time_t prev_reply_diff;
	int ret;

	do {
		if (conn->ld == NULL)
			return;

		i_zero(&timeout);
		ret = ldap_result(conn->ld, LDAP_RES_ANY, 0, &timeout, &msg);
#ifdef OPENLDAP_ASYNC_WORKAROUND
		if (ret == 0) {
			/* try again, there may be another in buffer */
			ret = ldap_result(conn->ld, LDAP_RES_ANY, 0,
					  &timeout, &msg);
		}
#endif
		if (ret <= 0)
			break;

		res = i_new(struct db_ldap_result, 1);
		res->refcount = 1;
		res->msg = msg;
		db_ldap_handle_result(conn, res);
		db_ldap_result_unref(&res);
	} while (conn->io != NULL);

	prev_reply_diff = ioloop_time - conn->last_reply_stamp;
	conn->last_reply_stamp = ioloop_time;

	if (ret > 0) {
		/* input disabled, continue once it's enabled */
		i_assert(conn->io == NULL);
	} else if (ret == 0) {
		/* send more requests */
		while (db_ldap_request_queue_next(conn))
			;
	} else if (ldap_get_errno(conn) != LDAP_SERVER_DOWN) {
		e_error(conn->event, "ldap_result() failed: %s", ldap_get_error(conn));
		ldap_conn_reconnect(conn);
	} else if (aqueue_count(conn->request_queue) > 0 ||
		   prev_reply_diff < DB_LDAP_IDLE_RECONNECT_SECS) {
		e_error(conn->event, "Connection lost to LDAP server, reconnecting");
		ldap_conn_reconnect(conn);
	} else {
		/* server probably disconnected an idle connection. don't
		   reconnect until the next request comes. */
		db_ldap_conn_close(conn);
	}
}

#ifdef HAVE_LDAP_SASL
static int
sasl_interact(LDAP *ld ATTR_UNUSED, unsigned int flags ATTR_UNUSED,
	      void *defaults, void *interact)
{
	struct db_ldap_sasl_bind_context *context = defaults;
	sasl_interact_t *in;
	const char *str;

	for (in = interact; in->id != SASL_CB_LIST_END; in++) {
		switch (in->id) {
		case SASL_CB_GETREALM:
			str = context->realm;
			break;
		case SASL_CB_AUTHNAME:
			str = context->authcid;
			break;
		case SASL_CB_USER:
			str = context->authzid;
			break;
		case SASL_CB_PASS:
			str = context->passwd;
			break;
		default:
			str = NULL;
			break;
		}
		if (str != NULL) {
			in->len = strlen(str);
			in->result = str;
		}
	}
	return LDAP_SUCCESS;
}
#endif

static void ldap_connection_timeout(struct ldap_connection *conn)
{
	i_assert(conn->conn_state == LDAP_CONN_STATE_BINDING);

	e_error(conn->event, "Initial binding to LDAP server timed out");
	db_ldap_conn_close(conn);
}

#ifdef HAVE_LDAP_SASL
static int db_ldap_bind_sasl(struct ldap_connection *conn)
{
	struct db_ldap_sasl_bind_context context;
	int ret;

	i_zero(&context);
	context.authcid = conn->set->auth_dn;
	context.passwd = conn->set->auth_dn_password;
	context.realm = conn->set->auth_sasl_realm;
	context.authzid = conn->set->auth_sasl_authz_id;

	const char *mechs = t_array_const_string_join(
		&conn->set->auth_sasl_mechanisms, " ");

	/* There doesn't seem to be a way to do SASL binding
	   asynchronously.. */
	ret = ldap_sasl_interactive_bind_s(conn->ld, NULL, mechs,
					   NULL, NULL, LDAP_SASL_QUIET,
					   sasl_interact, &context);
	if (db_ldap_connect_finish(conn, ret) < 0)
		return -1;

	conn->conn_state = LDAP_CONN_STATE_BOUND_DEFAULT;

	return 0;
}
#else
static int db_ldap_bind_sasl(struct ldap_connection *conn ATTR_UNUSED)
{
	i_unreached(); /* already checked at init */

	return -1;
}
#endif

static int db_ldap_bind_simple(struct ldap_connection *conn)
{
	int msgid;

	i_assert(conn->conn_state != LDAP_CONN_STATE_BINDING);
	i_assert(conn->default_bind_msgid == -1);
	i_assert(conn->pending_count == 0);

	struct berval creds = {
		.bv_val = (char*)conn->set->auth_dn_password,
		.bv_len = strlen(conn->set->auth_dn_password)
	};

	int ret = ldap_sasl_bind(conn->ld, conn->set->auth_dn, LDAP_SASL_SIMPLE,
				 &creds, NULL, NULL, &msgid);
	if (ret != LDAP_SUCCESS) {
		i_assert(ldap_get_errno(conn) != LDAP_SUCCESS);
		if (db_ldap_connect_finish(conn, ldap_get_errno(conn)) < 0) {
			/* lost connection, close it */
			db_ldap_conn_close(conn);
		}
		return -1;
	}

	conn->conn_state = LDAP_CONN_STATE_BINDING;
	conn->default_bind_msgid = msgid;

	timeout_remove(&conn->to);
	conn->to = timeout_add(DB_LDAP_REQUEST_LOST_TIMEOUT_SECS*1000,
			       ldap_connection_timeout, conn);
	return 0;
}

static int db_ldap_bind(struct ldap_connection *conn)
{
	int ret;
	if (array_is_empty(&conn->set->auth_sasl_mechanisms))
		ret = db_ldap_bind_simple(conn);
	else
		ret = db_ldap_bind_sasl(conn);
	return ret < 0 ? -1 : 0;
}

static void db_ldap_get_fd(struct ldap_connection *conn)
{
	int ret;

	/* get the connection's fd */
	ret = ldap_get_option(conn->ld, LDAP_OPT_DESC, (void *)&conn->fd);
	if (ret != LDAP_SUCCESS) {
		i_fatal("%sCan't get connection fd: %s",
			conn->log_prefix, ldap_err2string(ret));
	}
	if (conn->fd <= STDERR_FILENO) {
		/* Solaris LDAP library seems to be broken */
		i_fatal("%sBuggy LDAP library returned wrong fd: %d",
			conn->log_prefix, conn->fd);
	}
	i_assert(conn->fd != -1);
	net_set_nonblock(conn->fd, TRUE);
}

static const char *
db_ldap_log_callback(struct ldap_connection *conn)
{
	return conn->log_prefix;
}

static int
db_ldap_add_connection_callback(LDAP *ld ATTR_UNUSED, Sockbuf *sb ATTR_UNUSED,
				LDAPURLDesc *srv, struct sockaddr *addr ATTR_UNUSED,
				struct ldap_conncb *ctx)
{
	struct ldap_connection *conn = ctx->lc_arg;
	const char *prefix = t_strdup_printf("ldap(%s://%s:%d): ",
		srv->lud_scheme, srv->lud_host, srv->lud_port);

	if (strcmp(conn->log_prefix, prefix) != 0) {
		i_free(conn->log_prefix);
		conn->log_prefix = i_strdup(prefix);
	}
	return LDAP_SUCCESS;
}

static void
db_ldap_del_connection_callback(LDAP *ld ATTR_UNUSED, Sockbuf *sb ATTR_UNUSED,
				struct ldap_conncb *ctx ATTR_UNUSED)
{
	/* does nothing, but must exist in struct ldap_conncb */
}

static void ldap_set_options(struct ldap_connection *conn)
{
	const char *error;
	int ret;

	struct ldap_conncb *cb = p_new(conn->pool, struct ldap_conncb, 1);
	cb->lc_add = db_ldap_add_connection_callback;
	cb->lc_del = db_ldap_del_connection_callback;
	cb->lc_arg = conn;
	ret = ldap_set_option(conn->ld, LDAP_OPT_CONNECT_CB, cb);
	if (ret != LDAP_SUCCESS)
		i_fatal("%sCan't set conn_callbacks: %s",
			conn->log_prefix, ldap_err2string(ret));

#ifdef LDAP_OPT_NETWORK_TIMEOUT
	struct timeval tv;

	tv.tv_sec = DB_LDAP_CONNECT_TIMEOUT_SECS; tv.tv_usec = 0;
	ret = ldap_set_option(conn->ld, LDAP_OPT_NETWORK_TIMEOUT, &tv);
	if (ret != LDAP_SUCCESS)
		i_fatal("%sCan't set network-timeout: %s",
			conn->log_prefix, ldap_err2string(ret));
#endif

	if (ldap_set_opt(conn->ld, LDAP_OPT_DEREF, &conn->set->parsed_deref,
			 "ldap_deref", conn->set->deref, &error) < 0)
		i_fatal("%s%s", conn->log_prefix, error);
#ifdef LDAP_OPT_DEBUG_LEVEL
	if (conn->set->debug_level != 0) {
		if (ldap_set_opt(NULL, LDAP_OPT_DEBUG_LEVEL, &conn->set->debug_level,
				"ldap_debug_level", dec2str(conn->set->debug_level), &error) < 0)
			i_fatal("%s%s", conn->log_prefix, error);
		event_set_forced_debug(conn->event, TRUE);
	}
#endif

	if (ldap_set_opt(conn->ld, LDAP_OPT_PROTOCOL_VERSION,
			 &conn->set->version, "ldap_version",
			 dec2str(conn->set->version), &error) < 0)
		i_fatal("%s%s", conn->log_prefix, error);
	if (ldap_set_tls_options(conn->ld, conn->set->starttls,
				 conn->set->uris, conn->ssl_set, &error) < 0)
		i_fatal("%s%s", conn->log_prefix, error);
}

static void db_ldap_init_ld(struct ldap_connection *conn)
{
	int ret = ldap_initialize(&conn->ld, conn->set->uris);
	if (ret != LDAP_SUCCESS) {
		i_fatal("%sldap_initialize() failed: %s",
			conn->log_prefix, ldap_err2string(ret));
	}
	ldap_set_options(conn);
}

int db_ldap_connect(struct ldap_connection *conn)
{
	struct timeval start, end;
	int ret;

	if (conn->conn_state != LDAP_CONN_STATE_DISCONNECTED)
		return 0;

	i_gettimeofday(&start);
	i_assert(conn->pending_count == 0);

	if (conn->delayed_connect) {
		conn->delayed_connect = FALSE;
		timeout_remove(&conn->to);
	}
	if (conn->ld == NULL)
		db_ldap_init_ld(conn);

	if (conn->set->starttls) {
		ret = ldap_start_tls_s(conn->ld, NULL, NULL);
		if (ret != LDAP_SUCCESS) {
			if (ret == LDAP_OPERATIONS_ERROR &&
			    *conn->set->uris != '\0' &&
			    str_begins_with(conn->set->uris, "ldaps:")) {
				i_fatal("%sDon't use both ldap_starttls=yes and ldaps URI",
					conn->log_prefix);
			}
			e_error(conn->event, "ldap_start_tls_s() failed: %s",
				ldap_err2string(ret));
			return -1;
		}
	}

	if (db_ldap_bind(conn) < 0)
		return -1;

	i_gettimeofday(&end);
	e_debug(conn->event, "initialization took %lld msecs",
		timeval_diff_msecs(&end, &start));

	db_ldap_get_fd(conn);
	conn->io = io_add(conn->fd, IO_READ, ldap_input, conn);
	return 0;
}

static void db_ldap_connect_callback(struct ldap_connection *conn)
{
	i_assert(conn->conn_state == LDAP_CONN_STATE_DISCONNECTED);
	(void)db_ldap_connect(conn);
}

void db_ldap_connect_delayed(struct ldap_connection *conn)
{
	if (conn->delayed_connect)
		return;
	conn->delayed_connect = TRUE;

	i_assert(conn->to == NULL);
	conn->to = timeout_add_short(0, db_ldap_connect_callback, conn);
}

void db_ldap_enable_input(struct ldap_connection *conn, bool enable)
{
	if (!enable) {
		io_remove(&conn->io);
	} else {
		if (conn->io == NULL && conn->fd != -1) {
			conn->io = io_add(conn->fd, IO_READ, ldap_input, conn);
			ldap_input(conn);
		}
	}
}

static void db_ldap_disconnect_timeout(struct ldap_connection *conn)
{
	db_ldap_abort_requests(conn, UINT_MAX,
		DB_LDAP_REQUEST_DISCONNECT_TIMEOUT_SECS, FALSE,
		"Aborting (timeout), we're not connected to LDAP server");

	if (aqueue_count(conn->request_queue) == 0) {
		/* no requests left, remove this timeout handler */
		timeout_remove(&conn->to);
	}
}

static void db_ldap_conn_close(struct ldap_connection *conn)
{
	struct ldap_request *const *requests, *request;
	unsigned int i;

	conn->conn_state = LDAP_CONN_STATE_DISCONNECTED;
	conn->delayed_connect = FALSE;
	conn->default_bind_msgid = -1;

	timeout_remove(&conn->to);

	if (conn->pending_count != 0) {
		requests = array_front(&conn->request_array);
		for (i = 0; i < conn->pending_count; i++) {
			request = requests[aqueue_idx(conn->request_queue, i)];

			i_assert(request->msgid != -1);
			request->msgid = -1;
		}
		conn->pending_count = 0;
	}

	if (conn->ld != NULL) {
		ldap_unbind_ext(conn->ld, NULL, NULL);
		conn->ld = NULL;
	}
	conn->fd = -1;

	/* the fd may have already been closed before ldap_unbind(),
	   so we'll have to use io_remove_closed(). */
	io_remove_closed(&conn->io);

	if (aqueue_count(conn->request_queue) > 0) {
		conn->to = timeout_add(DB_LDAP_REQUEST_DISCONNECT_TIMEOUT_SECS *
				       1000/2, db_ldap_disconnect_timeout, conn);
	}
}

static bool
db_ldap_is_sensitive_field(const char *name)
{
	return strstr(name, "nonce") != NULL ||
	       strstr(name, "password") != NULL ||
	       strstr(name, "secret") != NULL ||
	       str_ends_with(name, "key") ||
	       str_ends_with(name, "pass");
}

void db_ldap_get_attribute_names(pool_t pool,
				 const ARRAY_TYPE(const_string) *attrlist,
				 const char *const **attr_names_r,
				 const char *const **sensitive_r,
				 const char *skip_attr)
{
	unsigned int count = array_is_empty(attrlist) ? 0 : array_count(attrlist);
	i_assert(count % 2 == 0);

	ARRAY_TYPE(const_string) attr_names;
	ARRAY_TYPE(const_string) sensitive_attr_names;

	p_array_init(&attr_names, pool, count / 2);
	p_array_init(&sensitive_attr_names, pool, 2);
	string_t *tmp_str = t_str_new(128);

	for (unsigned int index = 0; index < count; ) {
		struct var_expand_program *prog;
		const char *name = array_idx_elem(attrlist, index++);
		const char *value = array_idx_elem(attrlist, index++);

		if (skip_attr != NULL && strcmp(skip_attr, name) == 0)
			continue;

		const char *error ATTR_UNUSED;
		str_truncate(tmp_str, 0);

		/* Mark the current end of the array before adding the elements
		   from the expansion of the field expression. This will be
		   used later to see which elements have been added. */
		unsigned int index = array_count(&attr_names);

		if (var_expand_program_create(value, &prog, &error) < 0) {
			e_debug(auth_event, "db-ldap: var_expand_program_create('%s') failed: %s", value, error);
			continue;
		}

		const char *const *vars = var_expand_program_variables(prog);
		for (; *vars != NULL; vars++) {
			const char *ldap_attr;
			if (str_begins(*vars, "ldap:", &ldap_attr) ||
			    str_begins(*vars, "ldap_multi:", &ldap_attr)) {
				/* when we free program, this name
				   would be invalid, so dup it here. */
				ldap_attr = p_strdup(pool, ldap_attr);
				array_push_back(&attr_names, &ldap_attr);
			}
		}
		var_expand_program_free(&prog);

		if (!db_ldap_is_sensitive_field(name))
			continue;

		/* We want to mark as sensitive ALL the LDAP attributes involved
		   in the creation of the "password" field. Typically this this
		   will be a single attribute, but the field value expression
		   allows for multiple attributes to be used. In this case, we
		   mark them all. */

		unsigned int count = array_count(&attr_names);
		/* Now index points to the first attribute newly added to
		   attr_names, and count points to the end of attr_names. */

		for (; index < count; index++) {
			const char *const *src = array_idx(&attr_names, index);
			array_push_back(&sensitive_attr_names, src);
		}
	}
	array_append_zero(&attr_names);
	array_append_zero(&sensitive_attr_names);

	*attr_names_r = array_front(&attr_names);
	if (sensitive_r != NULL)
		*sensitive_r = array_front(&sensitive_attr_names);
}

#define IS_LDAP_ESCAPED_CHAR(c) \
	((((unsigned char)(c)) & 0x80) != 0 || strchr(LDAP_ESCAPE_CHARS, (c)) != NULL)

const char *ldap_escape(const char *str,
			void *context ATTR_UNUSED)
{
	string_t *ret = NULL;

	for (const char *p = str; *p != '\0'; p++) {
		if (IS_LDAP_ESCAPED_CHAR(*p)) {
			if (ret == NULL) {
				ret = t_str_new((size_t) (p - str) + 64);
				str_append_data(ret, str, (size_t) (p - str));
			}
			str_printfa(ret, "\\%02X", (unsigned char)*p);
		} else if (ret != NULL)
			str_append_c(ret, *p);
	}

	return ret == NULL ? str : str_c(ret);
}

static bool
db_ldap_field_hide_password(struct db_ldap_result_iterate_context *ctx,
			    const char *attr)
{
	struct auth_request *request = ctx->ldap_request->auth_request;
	if (request->set->debug_passwords)
		return FALSE;

	if (ctx->sensitive_attr_names == NULL)
		return FALSE;

	return str_array_find(ctx->sensitive_attr_names, attr);
}

static void
get_ldap_fields(struct db_ldap_result_iterate_context *ctx,
		struct ldap_connection *conn, LDAPMessage *entry,
		const char *suffix)
{
	struct db_ldap_value *ldap_value;
	unsigned int i, count;
	BerElement *ber;

	char *attr = ldap_first_attribute(conn->ld, entry, &ber);
	while (attr != NULL) {
		struct berval **vals = ldap_get_values_len(conn->ld, entry, attr);

		ldap_value = p_new(ctx->pool, struct db_ldap_value, 1);
		if (vals == NULL) {
			ldap_value->values = p_new(ctx->pool, const char *, 1);
			count = 0;
		} else
			count = ldap_count_values_len(vals);

		ldap_value->values = p_new(ctx->pool, const char *, count + 1);
		for (i = 0; i < count; i++)
			ldap_value->values[i] = p_strndup(
				ctx->pool, vals[i]->bv_val, vals[i]->bv_len);

		str_printfa(ctx->debug, " %s%s=", attr, suffix);
		if (count == 0)
			str_append(ctx->debug, "<no values>");
		else if (db_ldap_field_hide_password(ctx, attr))
			str_append(ctx->debug, PASSWORD_HIDDEN_STR);
		else {
			str_append(ctx->debug, ldap_value->values[0]);
			for (i = 1; i < count; i++) {
				str_printfa(ctx->debug, ",%s",
					    ldap_value->values[0]);
			}
		}
		hash_table_insert(ctx->ldap_attrs,
				  p_strconcat(ctx->pool, attr, suffix, NULL),
				  ldap_value);

		ldap_value_free_len(vals);
		ldap_memfree(attr);
		attr = ldap_next_attribute(conn->ld, entry, ber);
	}
	ber_free(ber, 0);
}

struct db_ldap_result_iterate_context *
db_ldap_result_iterate_init_full(struct ldap_connection *conn,
				 struct ldap_request_search *ldap_request,
				 LDAPMessage *res, bool skip_null_values)
{
	struct db_ldap_result_iterate_context *ctx;
	const struct ldap_request_named_result *named_res;
	const char *suffix;
	pool_t pool;

	pool = pool_alloconly_create(MEMPOOL_GROWING"ldap result iter", 1024);
	ctx = p_new(pool, struct db_ldap_result_iterate_context, 1);
	ctx->pool = pool;
	ctx->ldap_request = &ldap_request->request;
	ctx->attr_next = ldap_request->attributes;
	ctx->sensitive_attr_names = ldap_request->sensitive_attr_names;
	ctx->skip_null_values = skip_null_values;
	hash_table_create(&ctx->ldap_attrs, pool, 0, strcase_hash, strcasecmp);
	ctx->var = str_new(ctx->pool, 256);
	ctx->debug = t_str_new(256);
	ctx->ldap_msg = res;
	ctx->ld = conn->ld;

	get_ldap_fields(ctx, conn, res, "");
	if (array_is_created(&ldap_request->named_results)) {
		array_foreach(&ldap_request->named_results, named_res) {
			suffix = t_strdup_printf("@%s", named_res->field->name);
			if (named_res->result != NULL) {
				get_ldap_fields(ctx, conn,
						named_res->result->msg, suffix);
			}
		}
	}
	return ctx;
}

struct db_ldap_result_iterate_context *
db_ldap_result_iterate_init(struct ldap_connection *conn,
			    struct ldap_request_search *ldap_request,
			    LDAPMessage *res, bool skip_null_values)
{
	return db_ldap_result_iterate_init_full(conn, ldap_request, res,
						skip_null_values);
}

const char *db_ldap_attribute_as_multi(const char *name)
{
	return t_strconcat(DB_LDAP_ATTR_MULTI_PREFIX, name, NULL);
}

static int
db_ldap_field_multi_expand(const char *data, const char **value_r,
			   void *context, const char **error_r)
{
	struct db_ldap_field_expand_context *ctx = context;
	struct auth_fields *fields = ctx->fields;
	const char *field_name = t_str_lcase(data);

	const char *value = auth_fields_find(fields,
					     db_ldap_attribute_as_multi(field_name));
	if (value == NULL || *value == '\0')
		value = auth_fields_find(fields, field_name);

	if (value == NULL || *value == '\0') {
		*error_r = t_strdup_printf("No such attribute '%s'", field_name);
		return -1;
	}
	*value_r = value;
	return 0;
}

static int
db_ldap_field_single_expand(const char *data, const char **value_r,
			    void *context, const char **error_r)
{
	struct db_ldap_field_expand_context *ctx = context;
	struct auth_fields *fields = ctx->fields;
	const char *field_name = t_str_lcase(data);

	if (strcmp(field_name, "dn") == 0) {
		/* DN must be always there */
		*value_r = auth_fields_find(fields, DB_LDAP_ATTR_DN);
		i_assert(*value_r != NULL);
		return 0;
	}

	*value_r = NULL;
	if (fields != NULL)
		*value_r = auth_fields_find(fields, field_name);

	if (*value_r == NULL || **value_r == '\0') {
		*error_r = t_strdup_printf("No such attribute '%s'", field_name);
		return -1;
	} else if (auth_fields_find(fields,
				  db_ldap_attribute_as_multi(field_name)) != NULL) {
		e_warning(ctx->event, "Multiple values found for '%s': "
			              "using value '%s'", field_name, *value_r);
	}

	return 0;
}

const struct var_expand_provider db_ldap_field_expand_fn_table[] = {
	{ "ldap",       db_ldap_field_single_expand },
	{ "ldap_multi", db_ldap_field_multi_expand },
	{ NULL, NULL }
};

struct auth_fields *
ldap_query_get_fields(pool_t pool,
		      struct ldap_connection *conn,
		      struct ldap_request_search *ldap_request,
		      LDAPMessage *res, bool skip_null_values)
{
	struct auth_fields *fields = auth_fields_init(pool);
	struct db_ldap_result_iterate_context *ldap_iter;
	const char *name, *const *values;

	const char *dn = ldap_get_dn(conn->ld, res);
	auth_fields_add(fields, DB_LDAP_ATTR_DN, dn, 0);

	ldap_iter = db_ldap_result_iterate_init(conn, ldap_request, res,
						skip_null_values);
	while (db_ldap_result_iterate_next(ldap_iter, &name, &values)) {
		/* normalize to lower case, as ldap names are case-insensitive. */
		name = t_str_lcase(name);
		auth_fields_add(fields, name, values[0], 0);
		if (values[0] != NULL && values[1] != NULL) {
			const char *mname = db_ldap_attribute_as_multi(name);
			string_t *mvalue = t_str_new(32);
			for (; *values != NULL; values++) {
				str_append_tabescaped(mvalue, *values);
				str_append_c(mvalue, '\t');
			}
			/* drop last \t */
			str_truncate(mvalue, str_len(mvalue) - 1);
			auth_fields_add(fields, mname, str_c(mvalue), 0);
		}
	}
	db_ldap_result_iterate_deinit(&ldap_iter);
	return fields;
}

static const char *const *
db_ldap_result_return_value(struct db_ldap_result_iterate_context *ctx,
			    struct db_ldap_value *ldap_value)
{
	if (ldap_value != NULL && ldap_value->values[0] != NULL)
		return ldap_value->values;

	/* LDAP attribute doesn't exist */
	ctx->val_1_arr[0] = "";
	return ctx->val_1_arr;
}

bool db_ldap_result_iterate_next(struct db_ldap_result_iterate_context *ctx,
				 const char **name_r,
				 const char *const **values_r)
{
	const char *name = *ctx->attr_next;
	if (name == NULL)
		return FALSE;

	ctx->attr_next++;

	struct db_ldap_value *ldap_value = hash_table_lookup(ctx->ldap_attrs, name);
	if (ldap_value != NULL)
		ldap_value->used = TRUE;
	else
		str_printfa(ctx->debug, "; %s missing", name);

	str_truncate(ctx->var, 0);
	*name_r = name;
	*values_r = db_ldap_result_return_value(ctx, ldap_value);
	if (ctx->skip_null_values && (*values_r)[0] == NULL) {
		/* no values. don't confuse the caller with this reply. */
		return db_ldap_result_iterate_next(ctx, name_r, values_r);
	}
	return TRUE;
}

static void
db_ldap_result_finish_debug(struct db_ldap_result_iterate_context *ctx)
{
	struct hash_iterate_context *iter;
	char *name;
	struct db_ldap_value *value;
	unsigned int unused_count = 0;
	size_t orig_len;

	if (ctx->ldap_request->result_logged)
		return;

	i_assert(ctx->debug != NULL);
	orig_len = str_len(ctx->debug);
	if (orig_len == 0) {
		e_debug(authdb_event(ctx->ldap_request->auth_request),
		        "no fields returned by the server");
		return;
	}

	str_append(ctx->debug, "; ");

	iter = hash_table_iterate_init(ctx->ldap_attrs);
	while (hash_table_iterate(iter, ctx->ldap_attrs, &name, &value)) {
		if (!value->used) {
			str_printfa(ctx->debug, "%s,", name);
			unused_count++;
		}
	}
	hash_table_iterate_deinit(&iter);

	if (unused_count == 0)
		str_truncate(ctx->debug, orig_len);
	else {
		str_truncate(ctx->debug, str_len(ctx->debug)-1);
		str_append(ctx->debug, " unused");
	}
	e_debug(authdb_event(ctx->ldap_request->auth_request),
		"result: %s", str_c(ctx->debug) + 1);

	ctx->ldap_request->result_logged = TRUE;
}

void db_ldap_result_iterate_deinit(struct db_ldap_result_iterate_context **_ctx)
{
	struct db_ldap_result_iterate_context *ctx = *_ctx;

	*_ctx = NULL;

	db_ldap_result_finish_debug(ctx);
	hash_table_destroy(&ctx->ldap_attrs);
	pool_unref(&ctx->pool);
}

static struct ldap_connection *
db_ldap_conn_find(const struct ldap_settings *set, const struct ssl_settings *ssl_set)
{
	/* Note that set->connection_group is implicitly used to control
	   which settings can chare the same connections. Settings with
	   different values for set->connection_group will NOT share
	   the connection. */
	struct ldap_connection *conn;
	for (conn = ldap_connections; conn != NULL; conn = conn->next) {
		if (settings_equal(&ldap_setting_parser_info, set, conn->set, NULL) &&
		    settings_equal(&ssl_setting_parser_info, ssl_set, conn->ssl_set, NULL))
			return conn;
	}
	return NULL;
}

struct ldap_connection *db_ldap_init(struct event *event)
{
	const struct ldap_settings *set;
	const struct ssl_settings *ssl_set;
	const char *error;

	set     = settings_get_or_fatal(event, &ldap_setting_parser_info);
	if (ssl_client_settings_get(event, &ssl_set, &error) < 0 ||
	    ldap_setting_post_check(set, &error) < 0 ||
	    ldap_set_tls_validate(ssl_set, &error) < 0)
		i_fatal("%s: %s", set->uris, error);

	/* see if it already exists */
	struct ldap_connection *conn = db_ldap_conn_find(set, ssl_set);
	if (conn != NULL) {
		settings_free(ssl_set);
		settings_free(set);
		conn->refcount++;
		return conn;
	}

	pool_t pool = pool_alloconly_create("ldap_connection", 1024);
	conn = p_new(pool, struct ldap_connection, 1);
	conn->pool = pool;
	conn->refcount = 1;

        conn->set = set;
	conn->ssl_set = ssl_set;

	conn->conn_state = LDAP_CONN_STATE_DISCONNECTED;
	conn->default_bind_msgid = -1;
	conn->fd = -1;

	conn->event = event_create(auth_event);
	conn->log_prefix = i_strdup_printf("ldap(%s): ", set->uris);
	event_set_log_prefix_callback(conn->event, FALSE, db_ldap_log_callback, conn);

	i_array_init(&conn->request_array, 512);
	conn->request_queue = aqueue_init(&conn->request_array.arr);

	conn->next = ldap_connections;
        ldap_connections = conn;

	db_ldap_init_ld(conn);
	return conn;
}

void db_ldap_unref(struct ldap_connection **_conn)
{
        struct ldap_connection *conn = *_conn;
	struct ldap_connection **p;

	*_conn = NULL;
	i_assert(conn->refcount >= 0);
	if (--conn->refcount > 0)
		return;

	for (p = &ldap_connections; *p != NULL; p = &(*p)->next) {
		if (*p == conn) {
			*p = conn->next;
			break;
		}
	}

	db_ldap_abort_requests(conn, UINT_MAX, 0, FALSE, "Shutting down");
	i_assert(conn->pending_count == 0);
	db_ldap_conn_close(conn);
	i_assert(conn->to == NULL);

	array_free(&conn->request_array);
	aqueue_deinit(&conn->request_queue);

	settings_free(conn->ssl_set);
	settings_free(conn->set);

	event_unref(&conn->event);
	i_free(conn->log_prefix);

	pool_unref(&conn->pool);
}

#ifndef BUILTIN_LDAP
/* Building a plugin */
extern struct passdb_module_interface passdb_ldap_plugin;
extern struct userdb_module_interface userdb_ldap_plugin;

void authdb_ldap_init(void);
void authdb_ldap_deinit(void);

void authdb_ldap_init(void)
{
	passdb_register_module(&passdb_ldap_plugin);
	userdb_register_module(&userdb_ldap_plugin);

}
void authdb_ldap_deinit(void)
{
	passdb_unregister_module(&passdb_ldap_plugin);
	userdb_unregister_module(&userdb_ldap_plugin);
}
#endif

#endif
