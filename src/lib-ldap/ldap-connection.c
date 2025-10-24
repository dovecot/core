/* Copyright (c) 2016-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "aqueue.h"
#include "ioloop.h"
#include "ldap-private.h"
#include "settings.h"
#include "ldap-utils.h"

static
void ldap_connection_read_more(struct ldap_connection *conn);
static
int ldap_connect_next_message(struct ldap_connection *conn, struct ldap_op_queue_entry *req, bool *finished_r);
static
void ldap_connection_abort_request(struct ldap_op_queue_entry *req);
static
void ldap_connection_request_destroy(struct ldap_op_queue_entry **req);
static
int ldap_connection_connect(struct ldap_connection *conn);
static
void ldap_connection_send_next(struct ldap_connection *conn);

void ldap_connection_deinit(struct ldap_connection **_conn)
{
	struct ldap_connection *conn = *_conn;

	*_conn = NULL;

	ldap_connection_kill(conn);

	unsigned int n = aqueue_count(conn->request_queue);
	for (unsigned int i = 0; i < n; i++) {
		struct ldap_op_queue_entry *req =
			array_idx_elem(&conn->request_array,
				       aqueue_idx(conn->request_queue, i));
		timeout_remove(&req->to_abort);
	}
	aqueue_deinit(&conn->request_queue);
	settings_free(conn->ssl_set);
	settings_free(conn->set);
	event_unref(&conn->event);
	pool_unref(&conn->pool);
}

static
int ldap_connection_setup(struct ldap_connection *conn, const char **error_r)
{
	int ret, opt;

	ret = ldap_initialize(&conn->conn, conn->set->uris);
	if (ret != LDAP_SUCCESS) {
		*error_r = t_strdup_printf("ldap_initialize(uris=%s) failed: %s",
					   conn->set->uris, ldap_err2string(ret));
		return -1;
	}

	if (ldap_set_tls_options(conn->conn, conn->set->starttls,
				 conn->set->uris, conn->ssl_set, error_r) < 0)
		return -1;

#ifdef LDAP_OPT_X_TLS_PROTOCOL_MIN
	/* refuse to connect to SSLv2 as it's completely insecure */
	opt = LDAP_OPT_X_TLS_PROTOCOL_SSL3;
	ldap_set_option(conn->conn, LDAP_OPT_X_TLS_PROTOCOL_MIN, &opt);
#endif
	opt = conn->set->timeout_secs;
	/* default timeout */
	ldap_set_option(conn->conn, LDAP_OPT_TIMEOUT, &opt);
	ldap_set_option(conn->conn, LDAP_OPT_NETWORK_TIMEOUT, &opt);
	/* timelimit */
	ldap_set_option(conn->conn, LDAP_OPT_TIMELIMIT, &opt);

	opt = conn->set->debug_level;
	ldap_set_option(NULL, LDAP_OPT_DEBUG_LEVEL, &opt);

	opt = LDAP_VERSION3;
	ldap_set_option(conn->conn, LDAP_OPT_PROTOCOL_VERSION, &opt);

	ldap_set_option(conn->conn, LDAP_OPT_REFERRALS, 0);

#ifdef LDAP_OPT_X_TLS_NEWCTX
	opt = 0;
	ldap_set_option(conn->conn, LDAP_OPT_X_TLS_NEWCTX, &opt);
#endif

	return 0;
}

bool ldap_connection_have_settings(struct ldap_connection *conn,
				   const struct ldap_client_settings *set,
				   const struct ssl_settings *ssl_set)
{
	if (!settings_equal(&ldap_client_setting_parser_info,
			    conn->set, set, NULL))
		return FALSE;

	if (strstr(set->uris, "ldaps://") == NULL && !set->starttls)
	 	return TRUE;

	return settings_equal(&ssl_setting_parser_info,
			      conn->ssl_set, ssl_set, NULL);
}

int ldap_connection_init(struct ldap_client *client,
			 const struct ldap_client_settings *set,
			 const struct ssl_settings *ssl_set,
			 struct ldap_connection **conn_r, const char **error_r)
{
	i_assert(set->uris != NULL && set->uris[0] != '\0');

	pool_t pool = pool_alloconly_create("ldap connection", 1024);
	struct ldap_connection *conn = p_new(pool, struct ldap_connection, 1);
	conn->pool = pool;
	conn->event = event_create(ldap_client_get_event(client));
	conn->client = client;
	event_set_append_log_prefix(conn->event,
				    t_strdup_printf("ldap(%s): ", set->uris));

	pool_ref(set->pool);
	pool_ref(ssl_set->pool);

	conn->set = set;
	conn->ssl_set = ssl_set;

	/* deep copy relevant strings */
	if (*set->auth_dn_password != '\0')
		ber_str2bv(conn->set->auth_dn_password, strlen(conn->set->auth_dn_password), 0, &conn->cred);

	if (ldap_connection_setup(conn, error_r) < 0) {
		ldap_connection_deinit(&conn);
		return -1;
	}

	p_array_init(&conn->request_array, conn->pool, 10);
	conn->request_queue = aqueue_init(&conn->request_array.arr);

	*conn_r = conn;
	return 0;
}

void ldap_connection_switch_ioloop(struct ldap_connection *conn)
{
	if (conn->io != NULL)
		conn->io = io_loop_move_io(&conn->io);
	if (conn->to_disconnect != NULL)
		conn->to_disconnect = io_loop_move_timeout(&conn->to_disconnect);
	if (conn->to_reconnect != NULL)
		conn->to_reconnect = io_loop_move_timeout(&conn->to_reconnect);
	unsigned int n = aqueue_count(conn->request_queue);

	for (unsigned int i = 0; i < n; i++) {
		struct ldap_op_queue_entry *req =
			array_idx_elem(&conn->request_array,
				       aqueue_idx(conn->request_queue, i));
		if (req->to_abort != NULL)
			req->to_abort = io_loop_move_timeout(&req->to_abort);
	}
}

static void
ldap_connection_result_failure(struct ldap_connection *conn,
			       struct ldap_op_queue_entry *req,
			       int ret, const char *error)
{
	struct ldap_result res;
	i_zero(&res);
	res.conn = conn;
	res.openldap_ret = ret;
	res.error_string = error;
	if (req->result_callback != NULL)
		req->result_callback(&res, req->result_callback_ctx);
	else
		e_error(conn->event, "%s", error);
	ldap_connection_kill(conn);
}

static
void ldap_connection_result_success(struct ldap_connection *conn,
				    struct ldap_op_queue_entry *req)
{
	struct ldap_result res;
	i_zero(&res);
	res.conn = conn;
	res.openldap_ret = LDAP_SUCCESS;
	if (req->result_callback != NULL)
		req->result_callback(&res, req->result_callback_ctx);
}

static struct ldap_op_queue_entry *
ldap_connection_next_unsent_request(struct ldap_connection *conn,
				    unsigned int *index_r)
{
	struct ldap_op_queue_entry *last_req = NULL;
	*index_r = 0;

	for (unsigned int i = 0; i < aqueue_count(conn->request_queue); i++) {
		struct ldap_op_queue_entry *req =
			array_idx_elem(&conn->request_array,
				aqueue_idx(conn->request_queue, i));
		if (req->msgid > -1)
			break;
		*index_r = i;
		last_req = req;
	}
	return last_req;
}

static
void ldap_connection_send_next(struct ldap_connection *conn)
{
	unsigned int index;
	struct ldap_op_queue_entry *req;

	timeout_remove(&conn->to_reconnect);

	if (conn->state == LDAP_STATE_DISCONNECT) {
		if (ldap_connection_connect(conn) == -1)
			conn->to_reconnect = timeout_add(1000, ldap_connection_send_next, conn);
		return;
	}

	if (conn->state != LDAP_STATE_CONNECT) {
		return;
	}

	if (conn->pending > 10) return; /* try again later */

	req = ldap_connection_next_unsent_request(conn, &index);
	/* nothing to actually send */
	if (req == NULL) return;

	i_assert(req->msgid == -1);

	const char *error;
	int ret;
	if ((ret = req->send_request_cb(conn, req, &error)) != LDAP_SUCCESS) {
		/* did not succeed */
		struct ldap_result res;

		i_zero(&res);
		res.openldap_ret = ret;
		res.error_string = error;
		if (req->result_callback != NULL)
			req->result_callback(&res, req->result_callback_ctx);

		ldap_connection_request_destroy(&req);
		aqueue_delete(conn->request_queue, index);
	} else conn->pending++;
}

static
void ldap_connection_request_destroy(struct ldap_op_queue_entry **_req)
{
	struct ldap_op_queue_entry *req = *_req;

	*_req = NULL;

	timeout_remove(&req->to_abort);
	pool_unref(&req->pool);
}

void ldap_connection_queue_request(struct ldap_connection *conn, struct ldap_op_queue_entry *req)
{
	req->msgid = -1;
	req->conn = conn;
	aqueue_append(conn->request_queue, &req);
	if (req->timeout_secs > 0)
		req->to_abort = timeout_add(req->timeout_secs * 1000, ldap_connection_abort_request, req);

	ldap_connection_send_next(conn);
}

static int
ldap_connection_connect_parse(struct ldap_connection *conn,
			      struct ldap_op_queue_entry *req,
			      LDAPMessage *message, bool *finished_r)
{
	int ret, result_err;
	char *retoid, *result_errmsg;
	int msgtype = ldap_msgtype(message);

	*finished_r = TRUE;
	ret = ldap_parse_result(conn->conn, message, &result_err, NULL,
		&result_errmsg, NULL, NULL, 0);

	switch(conn->state) {
	case LDAP_STATE_TLS:
		if (msgtype != LDAP_RES_EXTENDED) {
			*finished_r = FALSE;
			return LDAP_SUCCESS;
		}
		if (ret != 0) {
			ldap_connection_result_failure(conn, req, ret, t_strdup_printf(
				"ldap_start_tls(uris=%s) failed: %s",
				conn->set->uris, ldap_err2string(ret)));
			return ret;
		} else if (result_err != 0) {
			ldap_connection_result_failure(conn, req, result_err, t_strdup_printf(
				"ldap_start_tls(uris=%s) failed: %s",
				conn->set->uris, result_errmsg));
			ldap_memfree(result_errmsg);
			return LDAP_INVALID_CREDENTIALS; /* make sure it disconnects */
		} else {
			ret = ldap_parse_extended_result(conn->conn, message, &retoid, NULL, 0);
			/* retoid can be NULL even if ret == 0 */
			if (ret == 0) {
				ret = ldap_install_tls(conn->conn);
				if (ret != 0) {
					// if this fails we have to abort
					ldap_connection_result_failure(conn, req, ret, t_strdup_printf(
						"ldap_start_tls(uris=%s) failed: %s",
						conn->set->uris, ldap_err2string(ret)));
					return LDAP_INVALID_CREDENTIALS;
				}
			}
			if (ret != LDAP_SUCCESS) {
				ldap_connection_result_failure(conn, req, ret, t_strdup_printf(
					"ldap_start_tls(uris=%s) failed: %s",
					conn->set->uris, ldap_err2string(ret)));
				return LDAP_UNAVAILABLE;
			} else {
				if (conn->set->debug_level > 0)
					e_debug(conn->event,
						"Using TLS connection to remote LDAP server");
			}
			ldap_memfree(retoid);
		}
		conn->state = LDAP_STATE_AUTH;
		return ldap_connect_next_message(conn, req, finished_r);
	case LDAP_STATE_AUTH:
		if (ret != LDAP_SUCCESS) {
			ldap_connection_result_failure(conn, req, ret, t_strdup_printf(
				"ldap_parse_result() failed for connect: %s",
				ldap_err2string(ret)));
			return ret;
		}
		if (result_err != LDAP_SUCCESS) {
			const char *error = result_errmsg != NULL ?
				result_errmsg : ldap_err2string(result_err);
				ldap_connection_result_failure(conn, req, result_err, t_strdup_printf(
				"Connect failed: %s", error));
			ldap_memfree(result_errmsg);
			return result_err;
		}
		if (msgtype != LDAP_RES_BIND) return 0;
		ret = ldap_parse_sasl_bind_result(conn->conn, message, &conn->scred, 0);
		if (ret != LDAP_SUCCESS) {
			const char *error = t_strdup_printf(
				"Cannot bind with server: %s", ldap_err2string(ret));
			ldap_connection_result_failure(conn, req, ret, error);
			return 1;
		}
		conn->state = LDAP_STATE_CONNECT;
		return ldap_connect_next_message(conn, req, finished_r);
	default:
		i_unreached();
	}
	i_unreached();
}

static
void ldap_connection_abort_request(struct ldap_op_queue_entry *req)
{
	struct ldap_result res;

	/* too bad */
	timeout_remove(&req->to_abort);
	if (req->msgid > -1)
		ldap_abandon_ext(req->conn->conn, req->msgid, NULL, NULL);

	i_zero(&res);
	res.openldap_ret = LDAP_TIMEOUT;
	res.error_string = "Aborting LDAP request after timeout";
	if (req->result_callback != NULL)
		req->result_callback(&res, req->result_callback_ctx);

	unsigned int n = aqueue_count(req->conn->request_queue);
	for (unsigned int i = 0; i < n; i++) {
		struct ldap_op_queue_entry *arr_req =
			array_idx_elem(&req->conn->request_array,
				       aqueue_idx(req->conn->request_queue, i));
		if (req == arr_req) {
			aqueue_delete(req->conn->request_queue, i);
			ldap_connection_request_destroy(&req);
			return;
		}
	}
	i_unreached();
}

static
void ldap_connection_abort_all_requests(struct ldap_connection *conn)
{
	struct ldap_result res;
	i_zero(&res);
	res.openldap_ret = LDAP_TIMEOUT;
	res.error_string = "Aborting LDAP requests due to failure";

	unsigned int n = aqueue_count(conn->request_queue);
	for (unsigned int i = 0; i < n; i++) {
		struct ldap_op_queue_entry **reqp =
			array_idx_modifiable(&conn->request_array,
		aqueue_idx(conn->request_queue, i));
		timeout_remove(&(*reqp)->to_abort);
		if ((*reqp)->result_callback != NULL)
			(*reqp)->result_callback(&res, (*reqp)->result_callback_ctx);
		ldap_connection_request_destroy(reqp);
	}
	aqueue_clear(conn->request_queue);
}

static int
ldap_connect_next_message(struct ldap_connection *conn,
			  struct ldap_op_queue_entry *req, bool *finished_r)
{
	int ret;

	*finished_r = TRUE;

	switch(conn->state) {
	case LDAP_STATE_DISCONNECT:
		if (conn->set->starttls && strstr(conn->set->uris, "ldaps://") == NULL) {
			ret = ldap_start_tls(conn->conn, NULL, NULL, &req->msgid);
			if (ret != LDAP_SUCCESS) {
				ldap_connection_result_failure(conn, req, ret, t_strdup_printf(
					"ldap_start_tls(uris=%s) failed: %s",
					conn->set->uris, ldap_err2string(ret)));
				return ret;
			}
			conn->state = LDAP_STATE_TLS;
			break;
		}
		conn->state = LDAP_STATE_AUTH;
		/* fall through */
	case LDAP_STATE_AUTH:
		ret = ldap_sasl_bind(conn->conn,
			conn->set->auth_dn,
			LDAP_SASL_SIMPLE,
			&conn->cred,
			NULL,
			NULL,
			&req->msgid);
		if (ret != LDAP_SUCCESS) {
			ldap_connection_result_failure(conn, req, ret, t_strdup_printf(
				"ldap_sasl_bind(uris=%s, dn=%s) failed: %s",
				conn->set->uris, conn->set->auth_dn, ldap_err2string(ret)));
			return ret;
		}
		break;
	case LDAP_STATE_CONNECT:
		ldap_connection_result_success(conn, req);
		return LDAP_SUCCESS; /* we are done here */
	default:
		i_unreached();
	};

	req->conn = conn;
	*finished_r = FALSE;
	return LDAP_SUCCESS;
}

static
int ldap_connection_connect(struct ldap_connection *conn)
{
	const char *error;
	int fd;
	Sockbuf *sb;
	bool finished;

	if (conn->conn == NULL) {
		/* try to reconnect after disconnection */
		if (ldap_connection_setup(conn, &error) < 0)
			e_error(conn->event, "%s", error);
	}

	pool_t pool = pool_alloconly_create(MEMPOOL_GROWING "ldap bind", 128);
	struct ldap_op_queue_entry *req = p_new(pool, struct ldap_op_queue_entry, 1);
	req->pool = pool;

	req->internal_response_cb = ldap_connection_connect_parse;
	req->timeout_secs = conn->set->timeout_secs;

	if (ldap_connect_next_message(conn, req, &finished) != LDAP_SUCCESS ||
	    conn->conn == NULL) {
		pool_unref(&pool);
		return -1;
	}
	conn->pending++;
	aqueue_append(conn->request_queue, &req);
	/* start timeout */
	if (req->timeout_secs > 0)
		req->to_abort = timeout_add(req->timeout_secs * 1000, ldap_connection_abort_request, req);

	ldap_get_option(conn->conn, LDAP_OPT_SOCKBUF, &sb);
	ber_sockbuf_ctrl(sb, LBER_SB_OPT_GET_FD, &fd);
	conn->io = io_add(fd, IO_READ, ldap_connection_read_more, conn);
	if (conn->set->max_idle_time_secs > 0)
		conn->to_disconnect = timeout_add(conn->set->max_idle_time_secs * 1000, ldap_connection_kill, conn);
	return 0;
}

void ldap_connection_kill(struct ldap_connection *conn)
{
	io_remove_closed(&conn->io);
	timeout_remove(&conn->to_disconnect);
	timeout_remove(&conn->to_reconnect);
	if (conn->request_queue != NULL) {
		unsigned int n = aqueue_count(conn->request_queue);

		for (unsigned int i = 0; i < n; i++) {
			struct ldap_op_queue_entry *req =
				array_idx_elem(&conn->request_array,
					       aqueue_idx(conn->request_queue, i));
			if (req->msgid > -1)
				ldap_abandon_ext(conn->conn, req->msgid, NULL, NULL);
			req->msgid = -1;
		}
	}
	if (conn->conn != NULL) {
		ldap_unbind_ext(conn->conn, NULL, NULL);
		ldap_memfree(conn->scred);
	}
	conn->conn = NULL;
	conn->state = LDAP_STATE_DISCONNECT;
}

int ldap_connection_check(struct ldap_connection *conn)
{
	/* it's not connected */
	if (conn->state == LDAP_STATE_DISCONNECT) return -1;
	return 0;
}

static struct ldap_op_queue_entry *
ldap_connection_find_req_by_msgid(struct ldap_connection *conn, int msgid,
				  unsigned int *idx_r)
{
	unsigned int i, n = aqueue_count(conn->request_queue);
	for (i = 0; i < n; i++) {
		struct ldap_op_queue_entry *req =
			array_idx_elem(&conn->request_array,
				       aqueue_idx(conn->request_queue, i));
		if (req->msgid == msgid) {
			*idx_r = i;
			return req;
		}
	}
	return NULL;
}

static int
ldap_connection_handle_message(struct ldap_connection *conn,
			       LDAPMessage *message)
{
	struct ldap_op_queue_entry *req;
	unsigned int i = 0;
	bool finished = FALSE;
	int err = LDAP_SUCCESS;

	/* we need to look at who it was for */
	req = ldap_connection_find_req_by_msgid(conn, ldap_msgid(message), &i);
	if (req != NULL)
		err = req->internal_response_cb(conn, req, message, &finished);
	ldap_msgfree(message);

	switch(err) {
	case LDAP_SUCCESS:
		break;
	case LDAP_SERVER_DOWN:
#ifdef LDAP_CONNECT_ERROR
	case LDAP_CONNECT_ERROR:
#endif
	case LDAP_UNAVAILABLE:
	case LDAP_OPERATIONS_ERROR:
	case LDAP_BUSY:
		/* requeue */
		ldap_connection_kill(conn);
		ldap_connection_send_next(conn);
		finished = FALSE;
		break;
	case LDAP_INVALID_CREDENTIALS: {
		/* fail everything */
		ldap_connection_kill(conn);
		ldap_connection_abort_all_requests(conn);
		return 0;
	}
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
	case LDAP_LOCAL_ERROR:
		finished = TRUE;
		break;
	default:
		/* ignore */
		break;
	}

	if (finished) {
		i_assert(req != NULL);
		ldap_connection_request_destroy(&req);
		conn->pending--;
		aqueue_delete(conn->request_queue, i);
		return 1;
	}
	return 0;
}

static
void ldap_connection_read_more(struct ldap_connection *conn)
{
	struct timeval tv = {
		.tv_sec = 0,
		.tv_usec = 0
	};

	LDAPMessage *message;
	int ret;

	/* try get a message */
	ret = ldap_result(conn->conn, LDAP_RES_ANY, 0, &tv, &message);
	if (ret > 0)
		ret = ldap_connection_handle_message(conn, message);

	if (ret == -1) {
		if (ldap_get_option(conn->conn, LDAP_OPT_RESULT_CODE, &ret) != LDAP_SUCCESS)
			i_unreached();
		if (ret != LDAP_SERVER_DOWN)
			e_error(conn->event,
				"ldap_result() failed: %s", ldap_err2string(ret));
		else
			e_error(conn->event,
				"Connection lost to LDAP server, reconnecting");
		/* kill me */
		ldap_connection_kill(conn);
	} else if (ret != 0) {
		ldap_connection_send_next(conn);
	}
	/* reset timeout */
	if (conn->to_disconnect != NULL)
		timeout_reset(conn->to_disconnect);
}

bool ldap_result_has_failed(struct ldap_result *result)
{
	i_assert((result->openldap_ret == LDAP_SUCCESS) == (result->error_string == NULL));
	return result->openldap_ret != LDAP_SUCCESS;
}

const char *ldap_result_get_error(struct ldap_result *result)
{
	i_assert((result->openldap_ret == LDAP_SUCCESS) == (result->error_string == NULL));
	return result->error_string;
}
