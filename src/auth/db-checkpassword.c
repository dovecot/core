/* Copyright (c) 2004-2012 Dovecot authors, see the included COPYING file */

#include "auth-common.h"

#if defined(PASSDB_CHECKPASSWORD) || defined(USERDB_CHECKPASSWORD)

#include "var-expand.h"
#include "db-checkpassword.h"

static void env_put_extra_fields(const char *extra_fields)
{
	const char *const *tmp;
	const char *key, *p;

	for (tmp = t_strsplit(extra_fields, "\t"); *tmp != NULL; tmp++) {
		key = t_str_ucase(t_strcut(*tmp, '='));
		p = strchr(*tmp, '=');
		if (p == NULL)
			env_put(t_strconcat(key, "=1", NULL));
		else
			env_put(t_strconcat(key, p, NULL));
	}
}

static void checkpassword_request_close(struct chkpw_auth_request *request)
{
	if (request->io_in != NULL)
		io_remove(&request->io_in);
	if (request->io_out != NULL)
		io_remove(&request->io_out);

	if (request->fd_in != -1) {
		if (close(request->fd_in) < 0)
			i_error("checkpassword: close() failed: %m");
		request->fd_in = -1;
	}
	if (request->fd_out != -1) {
		if (close(request->fd_out) < 0)
			i_error("checkpassword: close() failed: %m");
	}
}

void checkpassword_request_free(struct chkpw_auth_request *request)
{
	checkpassword_request_close(request);
	if (request->input_buf != NULL)
		str_free(&request->input_buf);

	if (request->password != NULL) {
		safe_memset(request->password, 0, strlen(request->password));
		i_free(request->password);
	}
	i_free(request);
}

enum checkpassword_sigchld_handler_result
checkpassword_sigchld_handler(const struct child_wait_status *child_wait_status,
			      struct chkpw_auth_request *request)
{
	int status = child_wait_status->status;
	pid_t pid = child_wait_status->pid;

	if (request == NULL) {
		i_error("checkpassword: sighandler called for unknown child %s",
			dec2str(pid));
		return SIGCHLD_RESULT_UNKNOWN_CHILD;
	}

	if (WIFSIGNALED(status)) {
		i_error("checkpassword: Child %s died with signal %d",
			dec2str(pid), WTERMSIG(status));
		return SIGCHLD_RESULT_DEAD_CHILD;
	} else if (WIFEXITED(status)) {
		request->exited = TRUE;
		request->exit_status = WEXITSTATUS(status);

		auth_request_log_debug(request->request,
				       "checkpassword", "exit_status=%d",
				       request->exit_status);
		return SIGCHLD_RESULT_OK;
	} else {
		/* shouldn't happen */
		auth_request_log_debug(request->request, "checkpassword",
				       "Child exited with status=%d", status);
		return SIGCHLD_RESULT_UNKNOWN_ERROR;
	}
}

static void env_put_auth_vars(struct auth_request *request)
{
	const struct var_expand_table *tab;
	unsigned int i;

	tab = auth_request_get_var_expand_table(request, NULL);
	for (i = 0; tab[i].key != '\0' || tab[i].long_key != NULL; i++) {
		if (tab[i].long_key != NULL && tab[i].value != NULL) {
			env_put(t_strdup_printf("AUTH_%s=%s",
						t_str_ucase(tab[i].long_key),
						tab[i].value));
		}
	}
}

void checkpassword_setup_env(struct auth_request *request)
{
	/* Besides passing the standard username and password in a
	   pipe, also pass some other possibly interesting information
	   via environment. Use UCSPI names for local/remote IPs. */
	env_put("PROTO=TCP"); /* UCSPI */
	env_put(t_strconcat("SERVICE=", request->service, NULL));
	if (request->local_ip.family != 0) {
		env_put(t_strconcat("TCPLOCALIP=",
				    net_ip2addr(&request->local_ip), NULL));
		/* FIXME: for backwards compatibility only,
		   remove some day */
		env_put(t_strconcat("LOCAL_IP=",
				    net_ip2addr(&request->local_ip), NULL));
	}
	if (request->remote_ip.family != 0) {
		env_put(t_strconcat("TCPREMOTEIP=",
				    net_ip2addr(&request->remote_ip), NULL));
		/* FIXME: for backwards compatibility only,
		   remove some day */
		env_put(t_strconcat("REMOTE_IP=",
				    net_ip2addr(&request->remote_ip), NULL));
	}
	if (request->local_port != 0) {
		env_put(t_strdup_printf("TCPLOCALPORT=%u",
					request->local_port));
	}
	if (request->remote_port != 0) {
		env_put(t_strdup_printf("TCPREMOTEPORT=%u",
					request->remote_port));
	}
	if (request->master_user != NULL) {
		env_put(t_strconcat("MASTER_USER=",
				    request->master_user, NULL));
	}
	if (request->extra_fields != NULL) {
		const char *fields =
			auth_stream_reply_export(request->extra_fields);

		/* extra fields could come from master db */
		env_put_extra_fields(fields);
	}
	env_put_auth_vars(request);
}

const char *
checkpassword_get_cmd(struct auth_request *request, const char *args,
		      const char *checkpassword_reply_path)
{
	string_t *str;

	str = t_str_new(256);
	var_expand(str, args,
		   auth_request_get_var_expand_table(request, NULL));
	return t_strconcat(str_c(str), " ", checkpassword_reply_path, NULL);
}

void checkpassword_child_input(struct chkpw_auth_request *request)
{
	unsigned char buf[1024];
	ssize_t ret;

	ret = read(request->fd_in, buf, sizeof(buf));
	if (ret <= 0) {
		if (ret < 0) {
			auth_request_log_error(request->request,
				"checkpassword", "read() failed: %m");
		}

		auth_request_log_debug(request->request, "checkpassword",
				       "Received no input");
		checkpassword_request_close(request);
		request->half_finish_callback(request);
	} else {
		if (request->input_buf == NULL)
			request->input_buf = str_new(default_pool, 512);
		str_append_n(request->input_buf, buf, ret);

		auth_request_log_debug(request->request, "checkpassword",
			"Received input: %s", str_c(request->input_buf));
	}
}

void checkpassword_child_output(struct chkpw_auth_request *request)
{
	/* Send: username \0 password \0 timestamp \0.
	   Must be 512 bytes or less. The "timestamp" parameter is actually
	   useful only for APOP authentication. We don't support it, so
	   keep it empty */
	struct auth_request *auth_request = request->request;
	buffer_t *buf;
	const unsigned char *data;
	size_t size;
	ssize_t ret;

	buf = buffer_create_dynamic(pool_datastack_create(), 512+1);
	buffer_append(buf, auth_request->user, strlen(auth_request->user)+1);
        if (request->password != NULL)
                buffer_append(buf, request->password, strlen(request->password)+1);
        else
                buffer_append_c(buf, '\0');
	buffer_append_c(buf, '\0');
	data = buffer_get_data(buf, &size);

	if (size > 512) {
		auth_request_log_error(request->request, "checkpassword",
			"output larger than 512 bytes: %"PRIuSIZE_T, size);
		request->finish_callback(request,
					 request->internal_failure_code);
		return;
	}

	ret = write(request->fd_out, data + request->write_pos,
		    size - request->write_pos);
	if (ret <= 0) {
		if (ret < 0) {
			auth_request_log_error(request->request,
				"checkpassword", "write() failed: %m");
		}
		request->finish_callback(request,
					 request->internal_failure_code);
		return;
	}

	request->write_pos += ret;
	if (request->write_pos < size)
		return;

	io_remove(&request->io_out);

	if (close(request->fd_out) < 0)
		i_error("checkpassword: close() failed: %m");
	request->fd_out = -1;
}

#endif
