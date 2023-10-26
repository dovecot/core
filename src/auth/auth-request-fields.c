/* Copyright (c) 2002-2020 Dovecot authors, see the included COPYING file */

#define AUTH_REQUEST_FIELDS_CONST

#include "auth-common.h"
#include "str.h"
#include "strescape.h"
#include "str-sanitize.h"
#include "auth-request.h"
#include "userdb-template.h"

void auth_request_fields_init(struct auth_request *request)
{
	request->fields.extra_fields = auth_fields_init(request->pool);
	if (request->mech != NULL) {
		request->fields.mech_name = request->mech->mech_name;
		event_add_str(request->event, "mechanism",
			      request->mech->mech_name);
	}
	/* Default to "insecure" until it's changed later */
	event_add_str(request->event, "transport", "insecure");
}

static void
auth_str_add_keyvalue(string_t *dest, const char *key, const char *value)
{
	str_append_c(dest, '\t');
	str_append(dest, key);
	if (value != NULL) {
		str_append_c(dest, '=');
		str_append_tabescaped(dest, value);
	}
}

static void
auth_request_export_fields(string_t *dest, struct auth_fields *auth_fields,
			   const char *prefix)
{
	const ARRAY_TYPE(auth_field) *fields = auth_fields_export(auth_fields);
	const struct auth_field *field;

	array_foreach(fields, field) {
		str_printfa(dest, "\t%s%s", prefix, field->key);
		if (field->value != NULL) {
			str_append_c(dest, '=');
			str_append_tabescaped(dest, field->value);
		}
	}
}

void auth_request_export(struct auth_request *request, string_t *dest)
{
	const struct auth_request_fields *fields = &request->fields;

	str_append(dest, "user=");
	str_append_tabescaped(dest, fields->user);

	auth_str_add_keyvalue(dest, "service", fields->service);

	if (fields->master_user != NULL)
		auth_str_add_keyvalue(dest, "master-user", fields->master_user);
	auth_str_add_keyvalue(dest, "original-username",
			      fields->original_username);
	if (fields->requested_login_user != NULL) {
		auth_str_add_keyvalue(dest, "requested-login-user",
				      fields->requested_login_user);
	}

	if (fields->local_ip.family != 0) {
		auth_str_add_keyvalue(dest, "lip",
				      net_ip2addr(&fields->local_ip));
	}
	if (fields->remote_ip.family != 0) {
		auth_str_add_keyvalue(dest, "rip",
				      net_ip2addr(&fields->remote_ip));
	}
	if (fields->local_port != 0)
		str_printfa(dest, "\tlport=%u", fields->local_port);
	if (fields->remote_port != 0)
		str_printfa(dest, "\trport=%u", fields->remote_port);
	if (fields->ssl_ja3_hash != NULL)
		auth_str_add_keyvalue(dest, "ssl_j3_hash", fields->ssl_ja3_hash);
	if (fields->real_local_ip.family != 0) {
		auth_str_add_keyvalue(dest, "real_lip",
				      net_ip2addr(&fields->real_local_ip));
	}
	if (fields->real_remote_ip.family != 0) {
		auth_str_add_keyvalue(dest, "real_rip",
				      net_ip2addr(&fields->real_remote_ip));
	}
	if (fields->real_local_port != 0)
		str_printfa(dest, "\treal_lport=%u", fields->real_local_port);
	if (fields->real_remote_port != 0)
		str_printfa(dest, "\treal_rport=%u", fields->real_remote_port);
	if (fields->local_name != 0) {
		str_append(dest, "\tlocal_name=");
		str_append_tabescaped(dest, fields->local_name);
	}
	if (fields->session_id != NULL) {
		str_append(dest, "\tsession=");
		str_append_tabescaped(dest, fields->session_id);
	}
	if (event_want_debug(request->event))
		str_append(dest, "\tdebug");
	switch (fields->conn_secured) {
	case AUTH_REQUEST_CONN_SECURED_NONE: break;
	case AUTH_REQUEST_CONN_SECURED: str_append(dest, "\tsecured"); break;
	case AUTH_REQUEST_CONN_SECURED_TLS: str_append(dest, "\tsecured=tls"); break;
	default: break;
	}
	if (fields->skip_password_check)
		str_append(dest, "\tskip-password-check");
	if (fields->delayed_credentials != NULL)
		str_append(dest, "\tdelayed-credentials");
	if (fields->valid_client_cert)
		str_append(dest, "\tvalid-client-cert");
	if (fields->no_penalty)
		str_append(dest, "\tno-penalty");
	if (fields->successful)
		str_append(dest, "\tsuccessful");
	if (fields->mech_name != NULL)
		auth_str_add_keyvalue(dest, "mech", fields->mech_name);
	if (fields->client_id != NULL)
		auth_str_add_keyvalue(dest, "client_id", fields->client_id);
	/* export passdb extra fields */
	auth_request_export_fields(dest, fields->extra_fields, "passdb_");
	/* export any userdb fields */
	if (fields->userdb_reply != NULL)
		auth_request_export_fields(dest, fields->userdb_reply, "userdb_");
}

bool auth_request_import_info(struct auth_request *request,
			      const char *key, const char *value)
{
	struct auth_request_fields *fields = &request->fields;
	struct event *event = request->event;

	i_assert(value != NULL);

	/* authentication and user lookups may set these */
	if (strcmp(key, "service") == 0) {
		fields->service = p_strdup(request->pool, value);
		event_add_str(event, "service", value);
	} else if (strcmp(key, "lip") == 0) {
		if (net_addr2ip(value, &fields->local_ip) < 0)
			return TRUE;
		event_add_ip(event, "local_ip", &fields->local_ip);
		if (fields->real_local_ip.family == 0)
			auth_request_import_info(request, "real_lip", value);
	} else if (strcmp(key, "rip") == 0) {
		if (net_addr2ip(value, &fields->remote_ip) < 0)
			return TRUE;
		event_add_ip(event, "remote_ip", &fields->remote_ip);
		if (fields->real_remote_ip.family == 0)
			auth_request_import_info(request, "real_rip", value);
	} else if (strcmp(key, "lport") == 0) {
		if (net_str2port(value, &fields->local_port) < 0)
			return TRUE;
		event_add_int(event, "local_port", fields->local_port);
		if (fields->real_local_port == 0)
			auth_request_import_info(request, "real_lport", value);
	} else if (strcmp(key, "rport") == 0) {
		if (net_str2port(value, &fields->remote_port) < 0)
			return TRUE;
		event_add_int(event, "remote_port", fields->remote_port);
		if (fields->real_remote_port == 0)
			auth_request_import_info(request, "real_rport", value);
	} else if (strcmp(key, "ssl_ja3_hash") == 0) {
		fields->ssl_ja3_hash = p_strdup(request->pool, value);
	} else if (strcmp(key, "real_lip") == 0) {
		if (net_addr2ip(value, &fields->real_local_ip) == 0)
			event_add_ip(event, "real_local_ip",
				     &fields->real_local_ip);
	} else if (strcmp(key, "real_rip") == 0) {
		if (net_addr2ip(value, &fields->real_remote_ip) == 0)
			event_add_ip(event, "real_remote_ip",
				     &fields->real_remote_ip);
	} else if (strcmp(key, "real_lport") == 0) {
		if (net_str2port(value, &fields->real_local_port) == 0)
			event_add_int(event, "real_local_port",
				      fields->real_local_port);
	} else if (strcmp(key, "real_rport") == 0) {
		if (net_str2port(value, &fields->real_remote_port) == 0)
			event_add_int(event, "real_remote_port",
				      fields->real_remote_port);
	} else if (strcmp(key, "local_name") == 0) {
		fields->local_name = p_strdup(request->pool, value);
		event_add_str(event, "local_name", value);
	} else if (strcmp(key, "session") == 0) {
		fields->session_id = p_strdup(request->pool, value);
		event_add_str(event, "session", value);
	} else if (strcmp(key, "debug") == 0)
		event_set_forced_debug(request->event, TRUE);
	else if (strcmp(key, "client_id") == 0) {
		fields->client_id = p_strdup(request->pool, value);
		event_add_str(event, "client_id", value);
	} else if (strcmp(key, "forward_fields") == 0) {
		auth_fields_import_prefixed(fields->extra_fields,
					    "forward_", value, 0);
		/* make sure the forward_ fields aren't deleted by
		   auth_fields_rollback() if the first passdb lookup fails. */
		auth_fields_snapshot(fields->extra_fields);
	} else
		return FALSE;
	/* NOTE: keep in sync with auth_request_export() */
	return TRUE;
}

bool auth_request_import_auth(struct auth_request *request,
			      const char *key, const char *value)
{
	struct auth_request_fields *fields = &request->fields;

	i_assert(value != NULL);

	if (auth_request_import_info(request, key, value))
		return TRUE;

	/* auth client may set these */
	if (strcmp(key, "secured") == 0) {
		if (strcmp(value, "tls") == 0) {
			fields->conn_secured = AUTH_REQUEST_CONN_SECURED_TLS;
			event_add_str(request->event, "transport", "TLS");
		} else {
			fields->conn_secured = AUTH_REQUEST_CONN_SECURED;
			event_add_str(request->event, "transport", "secured");
		}
	}
	else if (strcmp(key, "final-resp-ok") == 0)
		fields->final_resp_ok = TRUE;
	else if (strcmp(key, "no-penalty") == 0)
		fields->no_penalty = TRUE;
	else if (strcmp(key, "valid-client-cert") == 0)
		fields->valid_client_cert = TRUE;
	else if (strcmp(key, "cert_username") == 0) {
		if (request->set->ssl_username_from_cert && *value != '\0') {
			/* get username from SSL certificate. it overrides
			   the username given by the auth mechanism. */
			auth_request_set_username_forced(request, value);
			fields->cert_username = TRUE;
		}
	} else {
		return FALSE;
	}
	return TRUE;
}

bool auth_request_import(struct auth_request *request,
			 const char *key, const char *value)
{
	struct auth_request_fields *fields = &request->fields;

	i_assert(value != NULL);

	if (auth_request_import_auth(request, key, value))
		return TRUE;

	/* for communication between auth master and worker processes */
	if (strcmp(key, "user") == 0)
		auth_request_set_username_forced(request, value);
	else if (strcmp(key, "master-user") == 0) {
		fields->master_user = p_strdup(request->pool, value);
		event_add_str(request->event, "master_user", value);
	} else if (strcmp(key, "original-username") == 0) {
		fields->original_username = p_strdup(request->pool, value);
		event_add_str(request->event, "original_user", value);
	} else if (strcmp(key, "requested-login-user") == 0)
		auth_request_set_login_username_forced(request, value);
	else if (strcmp(key, "successful") == 0)
		auth_request_set_auth_successful(request);
	else if (strcmp(key, "skip-password-check") == 0)
		auth_request_set_password_verified(request);
	else if (strcmp(key, "delayed-credentials") == 0) {
		/* just make passdb_handle_credentials() work identically in
		   auth-worker as it does in auth-master. the worker shouldn't
		   care about the actual contents of the credentials. */
		fields->delayed_credentials = &uchar_nul;
		fields->delayed_credentials_size = 1;
	} else if (strcmp(key, "mech") == 0) {
		fields->mech_name = p_strdup(request->pool, value);
		event_add_str(request->event, "mechanism", value);
	} else if (str_begins(key, "passdb_", &key))
		auth_fields_add(fields->extra_fields, key, value, 0);
	else if (str_begins(key, "userdb_", &key)) {
		if (fields->userdb_reply == NULL)
			auth_request_init_userdb_reply(request, FALSE);
		auth_fields_add(fields->userdb_reply, key, value, 0);
	} else
		return FALSE;

	return TRUE;
}

static int
auth_request_fix_username(struct auth_request *request, const char **username,
			  const char **error_r)
{
	const struct auth_settings *set = request->set;
	unsigned char *p;
	char *user;

	if (*set->default_domain != '\0' &&
	    strchr(*username, '@') == NULL) {
		user = p_strconcat(unsafe_data_stack_pool, *username, "@",
				   set->default_domain, NULL);
	} else {
		user = t_strdup_noconst(*username);
	}

	for (p = (unsigned char *)user; *p != '\0'; p++) {
		if (set->username_translation_map[*p & 0xff] != 0)
			*p = set->username_translation_map[*p & 0xff];
		if (set->username_chars_map[*p & 0xff] == 0) {
			*error_r = t_strdup_printf(
				"Username character disallowed by auth_username_chars: "
				"0x%02x (username: %s)", *p,
				str_sanitize(*username, 128));
			return -1;
		}
	}

	if (*set->username_format != '\0') {
		/* username format given, put it through variable expansion.
		   we'll have to temporarily replace request->user to get
		   %u to be the wanted username */
		const char *error;
		string_t *dest;

		dest = t_str_new(256);
		unsigned int count = 0;
		const struct var_expand_table *table =
			auth_request_get_var_expand_table_full(request,
				user, NULL, &count);
		if (auth_request_var_expand_with_table(dest,
				set->username_format, request,
				table, NULL, &error) <= 0) {
			*error_r = t_strdup_printf(
				"Failed to expand username_format=%s: %s",
				set->username_format, error);
		}
		user = str_c_modifiable(dest);
	}

	if (user[0] == '\0') {
		/* Some PAM plugins go nuts with empty usernames */
		*error_r = "Empty username";
		return -1;
	}
	*username = user;
	return 0;
}

bool auth_request_set_username(struct auth_request *request,
			       const char *username, const char **error_r)
{
	const struct auth_settings *set = request->set;
	const char *p, *login_username = NULL;

	if (*set->master_user_separator != '\0' && !request->userdb_lookup) {
		/* check if the username contains a master user */
		p = strchr(username, *set->master_user_separator);
		if (p != NULL) {
			/* it does, set it. */
			login_username = t_strdup_until(username, p);

			/* username is the master user */
			username = p + 1;
		}
	}

	if (request->fields.original_username == NULL) {
		/* the username may change later, but we need to use this
		   username when verifying at least DIGEST-MD5 password. */
		request->fields.original_username =
			p_strdup(request->pool, username);
		event_add_str(request->event, "original_user",
			      request->fields.original_username);
	}
	if (request->fields.cert_username) {
		/* cert_username overrides the username given by
		   authentication mechanism. but still do checks and
		   translations to it. */
		username = request->fields.user;
	}

	if (auth_request_fix_username(request, &username, error_r) < 0) {
		request->fields.user = NULL;
		event_field_clear(request->event, "user");
		return FALSE;
	}
	auth_request_set_username_forced(request, username);
	if (request->fields.translated_username == NULL) {
		/* similar to original_username, but after translations */
		request->fields.translated_username = request->fields.user;
		event_add_str(request->event, "translated_user",
			      request->fields.translated_username);
	}
	request->user_changed_by_lookup = TRUE;

	if (login_username != NULL) {
		if (!auth_request_set_login_username(request,
						     login_username,
						     error_r))
			return FALSE;
	}
	return TRUE;
}

void auth_request_set_username_forced(struct auth_request *request,
				      const char *username)
{
	i_assert(username != NULL);

	request->fields.user = p_strdup(request->pool, username);
	event_add_str(request->event, "user", request->fields.user);
}

void auth_request_set_login_username_forced(struct auth_request *request,
					    const char *username)
{
	i_assert(username != NULL);

	request->fields.requested_login_user =
		p_strdup(request->pool, username);
	event_add_str(request->event, "login_user",
		      request->fields.requested_login_user);
}

bool auth_request_set_login_username(struct auth_request *request,
				     const char *username,
				     const char **error_r)
{
	struct auth_passdb *master_passdb;

	if (username[0] == '\0') {
		*error_r = "Master user login attempted to use empty login username";
		return FALSE;
	}

	if (strcmp(username, request->fields.user) == 0) {
		/* The usernames are the same, we don't really wish to log
		   in as someone else */
		return TRUE;
	}

	 /* lookup request->user from masterdb first */
	master_passdb = auth_request_get_auth(request)->masterdbs;
	if (master_passdb == NULL) {
		*error_r = "Master user login attempted without master passdbs";
		return FALSE;
	}
	request->passdb = master_passdb;

	if (auth_request_fix_username(request, &username, error_r) < 0) {
		request->fields.requested_login_user = NULL;
		event_field_clear(request->event, "login_user");
		return FALSE;
	}
	auth_request_set_login_username_forced(request, username);

	e_debug(request->event,
		"%sMaster user lookup for login: %s",
		auth_request_get_log_prefix_db(request),
		request->fields.requested_login_user);
	return TRUE;
}

void auth_request_master_user_login_finish(struct auth_request *request)
{
	if (request->failed)
		return;

	/* master login successful. update user and master_user variables. */
	e_info(authdb_event(request),
	       "Master user logging in as %s",
	       request->fields.requested_login_user);

	request->fields.master_user = request->fields.user;
	event_add_str(request->event, "master_user",
		      request->fields.master_user);

	auth_request_set_username_forced(request,
					 request->fields.requested_login_user);
	request->fields.translated_username = request->fields.requested_login_user;
	event_add_str(request->event, "translated_user",
		      request->fields.translated_username);
	request->fields.requested_login_user = NULL;
	event_field_clear(request->event, "login_user");
}

void auth_request_set_realm(struct auth_request *request, const char *realm)
{
	i_assert(realm != NULL);

	request->fields.realm = p_strdup(request->pool, realm);
	event_add_str(request->event, "realm", request->fields.realm);
}

void auth_request_set_auth_successful(struct auth_request *request)
{
	request->fields.successful = TRUE;
}

void auth_request_set_password_verified(struct auth_request *request)
{
	request->fields.skip_password_check = TRUE;
}

void auth_request_init_userdb_reply(struct auth_request *request,
				    bool add_default_fields)
{
	const char *error;

	request->fields.userdb_reply = auth_fields_init(request->pool);
	if (add_default_fields) {
		if (userdb_template_export(request->userdb->default_fields_tmpl,
					   request, &error) < 0) {
			e_error(authdb_event(request),
				"Failed to expand default_fields: %s", error);
		}
	}
}

void auth_request_set_delayed_credentials(struct auth_request *request,
					  const unsigned char *credentials,
					  size_t size)
{
	request->fields.delayed_credentials =
		p_memdup(request->pool, credentials, size);
	request->fields.delayed_credentials_size = size;
}
