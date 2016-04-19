/* Copyright (c) 2016 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "ldap-private.h"

static int
ldap_compare_callback(struct ldap_connection *conn,
		      struct ldap_op_queue_entry *req,
		      LDAPMessage *message, bool *finished_r)
{
	int msgtype = ldap_msgtype(message);
	struct ldap_result res;
	char *result_errmsg;
	int ret, result_err;

	if (msgtype != LDAP_RES_COMPARE) {
		*finished_r = FALSE;
		return 0;
	}
	*finished_r = TRUE;

	ret = ldap_parse_result(conn->conn, message,
				&result_err, NULL,
				&result_errmsg, NULL, NULL, 0);
	memset(&res, 0, sizeof(res));
	res.openldap_ret = ret;
	if (ret != LDAP_SUCCESS) {
		res.error_string = t_strdup_printf(
			"ldap_parse_result() failed to parse compare: %s",
			ldap_err2string(ret));
	} else if (result_err == LDAP_COMPARE_TRUE) {
		res.compare_true = TRUE;
	} else if (result_err == LDAP_COMPARE_FALSE) {
		res.compare_true = FALSE;
	} else {
		const struct ldap_compare_input *input = &req->input.compare;
		const char *error = result_errmsg != NULL ?
			result_errmsg : ldap_err2string(result_err);
		res.openldap_ret = result_err;
		res.error_string = t_strdup_printf(
			"ldap_compare_ext(dn=%s, attr=%s) failed: %s",
			input->dn, input->attr, error);
	}

	req->result_callback(&res, req->result_callback_ctx);

	if (result_errmsg != NULL)
		ldap_memfree(result_errmsg);
	return res.openldap_ret;
}

static int
ldap_compare_send(struct ldap_connection *conn, struct ldap_op_queue_entry *req,
		  const char **error_r)
{
	const struct ldap_compare_input *input = &req->input.compare;
	struct berval bv = {
		.bv_len = strlen(input->value),
		.bv_val = (void*)input->value
	};

	LDAPControl manageDSAIT = {
		LDAP_CONTROL_MANAGEDSAIT, {0, 0}, 0
	};

	/* try to use ManageDSAIT if available */
	LDAPControl *sctrls[] = {
		&manageDSAIT,
		NULL
	};

	int ret = ldap_compare_ext(conn->conn,
		input->dn,
		input->attr,
		&bv,
		sctrls,
		NULL,
		&(req->msgid));

	if (ret != LDAP_SUCCESS) {
		*error_r = t_strdup_printf(
			"ldap_compare_ext(dn=%s, attr=%s) failed: %s",
			input->dn, input->attr, ldap_err2string(ret));
	}
	return ret;
}

void ldap_connection_compare_start(struct ldap_connection *conn,
				   const struct ldap_compare_input *input,
				   ldap_result_callback_t *callback,
				   void *context)
{
	struct ldap_op_queue_entry *req;
	pool_t pool = pool_alloconly_create(MEMPOOL_GROWING "ldap compare", 128);
	req = p_new(pool, struct ldap_op_queue_entry, 1);
	req->pool = pool;

	req->internal_response_cb = ldap_compare_callback;

	req->input.compare = *input;
	req->result_callback = callback;
	req->result_callback_ctx = context;

	/* copy strings */
	req->input.compare.dn = p_strdup(req->pool, input->dn);
	req->input.compare.attr = p_strdup(req->pool, input->attr);
	req->input.compare.value = p_strdup(req->pool, input->value);

	req->send_request_cb = ldap_compare_send;
	req->timeout_secs = input->timeout_secs;

	return ldap_connection_queue_request(conn, req);
}

bool ldap_compare_result(struct ldap_result *result)
{
	i_assert(result->openldap_ret == LDAP_SUCCESS);
	i_assert(result->error_string == NULL);

	return result->compare_true;
}
