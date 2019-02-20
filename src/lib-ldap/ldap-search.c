/* Copyright (c) 2016-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "ldap-private.h"

#include <stdio.h>
#include <sys/time.h>

struct ldap_search_ctx {
	const struct ldap_search_input *input;
	struct ldap_result res;
};

static void
ldap_search_result_failure(struct ldap_op_queue_entry *req,
			   int ret, const char *error)
{
	struct ldap_search_ctx *sctx = req->ctx;
	sctx->res.openldap_ret = ret;
	sctx->res.error_string = error;
	req->result_callback(&sctx->res, req->result_callback_ctx);
}

static void ldap_search_result_success(struct ldap_op_queue_entry *req)
{
	struct ldap_search_ctx *sctx = req->ctx;
	sctx->res.openldap_ret = LDAP_SUCCESS;
	req->result_callback(&sctx->res, req->result_callback_ctx);
}

static int
ldap_search_callback(struct ldap_connection *conn,
		     struct ldap_op_queue_entry *req,
		     LDAPMessage *message, bool *finished_r)
{
	struct ldap_search_ctx *sctx = req->ctx;
	int msgtype = ldap_msgtype(message);
	char *result_errmsg = NULL;
	int ret, result_err;

	if (msgtype != LDAP_RES_SEARCH_ENTRY &&
	    msgtype != LDAP_RES_SEARCH_RESULT) {
		*finished_r = FALSE;
		return LDAP_SUCCESS;
	}
	*finished_r = TRUE;

	ret = ldap_parse_result(conn->conn, message, &result_err, NULL,
				&result_errmsg, NULL, NULL, 0);
	if (ret == LDAP_NO_RESULTS_RETURNED) {
		/*ret = LDAP_SUCCESS;*/
	} else if (ret != LDAP_SUCCESS) {
		ldap_search_result_failure(req, ret, t_strdup_printf(
			"ldap_parse_result() failed for search: %s", ldap_err2string(ret)));
		return ret;
	} else if (result_err != LDAP_SUCCESS) {
		const struct ldap_search_input *input = &req->input.search;
		const char *error = result_errmsg != NULL ?
			result_errmsg : ldap_err2string(result_err);
		ldap_search_result_failure(req, result_err, t_strdup_printf(
			"ldap_search_ext(base=%s, scope=%d, filter=%s) failed: %s",
			input->base_dn, input->scope, input->filter, error));
		ldap_memfree(result_errmsg);
		return result_err;
	}

	LDAPMessage *res = ldap_first_entry(conn->conn, message);

	while(res != NULL) {
		struct ldap_entry *obj = p_new(req->pool, struct ldap_entry, 1);
		ldap_entry_init(obj, &sctx->res, message);
		array_push_back(&sctx->res.entries, obj);
		res = ldap_next_entry(conn->conn, res);
	}

	if (msgtype == LDAP_RES_SEARCH_RESULT) {
		ldap_search_result_success(req);
		return LDAP_SUCCESS;
	}

	*finished_r = FALSE;
	return LDAP_SUCCESS;
}

static int
ldap_search_send(struct ldap_connection *conn, struct ldap_op_queue_entry *req,
		 const char **error_r)
{
	const struct ldap_search_input *input = &req->input.search;
	LDAPControl manageDSAIT = {
		LDAP_CONTROL_MANAGEDSAIT, {0, 0}, 0
	};
	/* try to use ManageDSAIT if available */
	LDAPControl *sctrls[] = {
		&manageDSAIT,
		NULL
	};

	struct timeval tv = {
		.tv_sec = req->timeout_secs,
		.tv_usec = 0
	};

	int ret = ldap_search_ext(conn->conn,
		input->base_dn,
		input->scope,
		input->filter,
		(char**)input->attributes,
		0,
		sctrls,
		NULL,
		&tv,
		input->size_limit,
		&req->msgid);

	if (ret != LDAP_SUCCESS) {
		*error_r = t_strdup_printf(
			"ldap_search_ext(base=%s, scope=%d, filter=%s) failed: %s",
			input->base_dn, input->scope, input->filter,
			ldap_err2string(ret));
	}
	return ret;
}

void ldap_connection_search_start(struct ldap_connection *conn,
				  const struct ldap_search_input *input,
				  ldap_result_callback_t *callback,
				  void *context)
{
	struct ldap_op_queue_entry *req;
	pool_t pool = pool_alloconly_create(MEMPOOL_GROWING "ldap search", 128);
	req = p_new(pool, struct ldap_op_queue_entry, 1);
	req->pool = pool;

	struct ldap_search_ctx *sctx = p_new(pool, struct ldap_search_ctx, 1);
	sctx->res.conn = conn;
	sctx->res.pool = pool;

	p_array_init(&sctx->res.entries, req->pool, 8);

	req->internal_response_cb = ldap_search_callback;

	req->result_callback = callback;
	req->result_callback_ctx = context;
	req->input.search = *input;

	/* copy strings */
	req->input.search.base_dn = p_strdup(req->pool, input->base_dn);
	req->input.search.filter = p_strdup(req->pool, input->filter);

	if (input->attributes != NULL) {
		ARRAY_TYPE(const_string) arr;
		p_array_init(&arr, req->pool, 8);
		for(const char **ptr = (const char**)input->attributes; *ptr != NULL; ptr++) {
			const char *tmp = p_strdup(req->pool, *ptr);
			array_push_back(&arr, &tmp);
		}
		array_append_zero(&arr);
		req->input.search.attributes = array_front_modifiable(&arr);
	}

	req->send_request_cb = ldap_search_send;
	sctx->input = &req->input.search;
	req->ctx = sctx;
	req->timeout_secs = input->timeout_secs;

	ldap_connection_queue_request(conn, req);
}
