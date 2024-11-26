/* Copyright (c) 2002-2018 Dovecot authors, see the included COPYING file */

#include "auth-common.h"
#include "array.h"
#include "password-scheme.h"
#include "auth-worker-connection.h"
#include "passdb.h"

static ARRAY(struct passdb_module_interface *) passdb_interfaces;
static ARRAY(struct passdb_module *) passdb_modules;

static const struct passdb_module_interface passdb_iface_deinit = {
	.name = "deinit"
};

static struct passdb_module_interface *passdb_interface_find(const char *name)
{
	struct passdb_module_interface *iface;

	array_foreach_elem(&passdb_interfaces, iface) {
		if (strcmp(iface->name, name) == 0)
			return iface;
	}
	return NULL;
}

void passdb_register_module(struct passdb_module_interface *iface)
{
	struct passdb_module_interface *old_iface;

	old_iface = passdb_interface_find(iface->name);
	if (old_iface != NULL && old_iface->verify_plain == NULL) {
		/* replacing a "support not compiled in" passdb */
		passdb_unregister_module(old_iface);
	} else if (old_iface != NULL) {
		i_panic("passdb_register_module(%s): Already registered",
			iface->name);
	}
	array_push_back(&passdb_interfaces, &iface);
}

void passdb_unregister_module(struct passdb_module_interface *iface)
{
	unsigned int idx;

	if (!array_lsearch_ptr_idx(&passdb_interfaces, iface, &idx))
		i_panic("passdb_unregister_module(%s): Not registered", iface->name);
	array_delete(&passdb_interfaces, idx, 1);
}

bool passdb_get_credentials(struct auth_request *auth_request,
			    const char *input, const char *input_scheme,
			    const unsigned char **credentials_r, size_t *size_r)
{
	const char *wanted_scheme = auth_request->wanted_credentials_scheme;
	const char *plaintext, *error;
	int ret;
	struct password_generate_params pwd_gen_params;

	if (auth_request->prefer_plain_credentials &&
	    password_scheme_is_alias(input_scheme, "PLAIN")) {
		/* we've a plaintext scheme and we prefer to get it instead
		   of converting it to the fallback scheme */
		wanted_scheme = "";
	}

	ret = password_decode(input, input_scheme,
			      credentials_r, size_r, &error);
	if (ret <= 0) {
		if (ret < 0) {
			e_error(authdb_event(auth_request),
				"Password data is not valid for scheme %s: %s",
				input_scheme, error);
		} else {
			e_error(authdb_event(auth_request),
				"Unknown scheme %s", input_scheme);
		}
		return FALSE;
	}

	if (*wanted_scheme == '\0') {
		/* anything goes. change the wanted_credentials_scheme to what
		   we actually got, so blocking passdbs work. */
		auth_request->wanted_credentials_scheme =
			p_strdup(auth_request->pool, t_strcut(input_scheme, '.'));
		return TRUE;
	}

	if (!password_scheme_is_alias(input_scheme, wanted_scheme)) {
		if (!password_scheme_is_alias(input_scheme, "PLAIN")) {
			const char *error = t_strdup_printf(
				"Requested %s scheme, but we have only %s",
				wanted_scheme, input_scheme);
			if (auth_request->set->debug_passwords) {
				error = t_strdup_printf("%s (input: %s)",
							error, input);
			}
			e_info(authdb_event(auth_request),
			       "%s", error);
			return FALSE;
		}

		/* we can generate anything out of plaintext passwords */
		plaintext = t_strndup(*credentials_r, *size_r);
		i_zero(&pwd_gen_params);
		pwd_gen_params.user = auth_request->fields.original_username;
		if (!auth_request->domain_is_realm &&
		    strchr(pwd_gen_params.user, '@') != NULL) {
			/* domain must not be used as realm. add the @realm. */
			pwd_gen_params.user = t_strconcat(pwd_gen_params.user, "@",
					       auth_request->fields.realm, NULL);
		}
		if (auth_request->set->debug_passwords) {
			e_debug(authdb_event(auth_request),
				"Generating %s from user '%s', password '%s'",
				wanted_scheme, pwd_gen_params.user, plaintext);
		}
		if (!password_generate(plaintext, &pwd_gen_params,
				       wanted_scheme, credentials_r, size_r)) {
			e_error(authdb_event(auth_request),
				"Requested unknown scheme %s", wanted_scheme);
			return FALSE;
		}
	}

	return TRUE;
}

void passdb_handle_credentials(enum passdb_result result,
			       const char *password, const char *scheme,
			       lookup_credentials_callback_t *callback,
                               struct auth_request *auth_request)
{
	const unsigned char *credentials = NULL;
	size_t size = 0;

	if (result != PASSDB_RESULT_OK) {
		callback(result, NULL, 0, auth_request);
		return;
	} else if (auth_fields_exists(auth_request->fields.extra_fields,
				      "noauthenticate")) {
		callback(PASSDB_RESULT_NEXT, NULL, 0, auth_request);
		return;
	}

	if (password != NULL) {
		if (!passdb_get_credentials(auth_request, password, scheme,
					    &credentials, &size))
			result = PASSDB_RESULT_SCHEME_NOT_AVAILABLE;
	} else if (*auth_request->wanted_credentials_scheme == '\0') {
		/* We're doing a passdb lookup (not authenticating).
		   Pass through a NULL password without an error. */
	} else if (auth_request->fields.delayed_credentials != NULL) {
		/* We already have valid credentials from an earlier
		   passdb lookup. auth_request_lookup_credentials_finish()
		   will use them. */
	} else {
		e_info(authdb_event(auth_request),
		       "Requested %s scheme, but we have a NULL password",
		       auth_request->wanted_credentials_scheme);
		result = PASSDB_RESULT_SCHEME_NOT_AVAILABLE;
	}

	callback(result, credentials, size, auth_request);
}

struct passdb_module *
passdb_preinit(pool_t pool, struct event *event,
	       const struct auth_passdb_settings *set)
{
	static unsigned int auth_passdb_id = 0;
	struct passdb_module_interface *iface;
	struct passdb_module *passdb;
	const char *error;

	iface = passdb_interface_find(set->driver);
	if (iface == NULL || iface->verify_plain == NULL) {
		/* maybe it's a plugin. try to load it. */
		auth_module_load(t_strconcat("authdb_", set->driver, NULL));
		iface = passdb_interface_find(set->driver);
	}
	if (iface == NULL)
		i_fatal("Unknown passdb driver '%s'", set->driver);
	if (iface->verify_plain == NULL) {
		i_fatal("Support not compiled in for passdb driver '%s'",
			set->driver);
	}

	if (iface->preinit != NULL) {
		if (iface->preinit(pool, event, &passdb, &error) < 0)
			i_fatal("passdb %s: %s", set->name, error);
		passdb->default_pass_scheme =
			set->default_password_scheme;
		passdb->blocking = set->use_worker;
	} else {
		passdb = p_new(pool, struct passdb_module, 1);
	}
	passdb->id = ++auth_passdb_id;
	passdb->iface = *iface;
	array_push_back(&passdb_modules, &passdb);
	return passdb;
}

void passdb_init(struct passdb_module *passdb)
{
	if (passdb->iface.init != NULL && passdb->init_refcount == 0)
		passdb->iface.init(passdb);
	passdb->init_refcount++;
}

void passdb_deinit(struct passdb_module *passdb)
{
	i_assert(passdb->init_refcount > 0);

	if (--passdb->init_refcount > 0)
		return;

	unsigned int i;
	if (!array_lsearch_ptr_idx(&passdb_modules, passdb, &i))
		i_unreached();
	array_delete(&passdb_modules, i, 1);

	if (passdb->iface.deinit != NULL)
		passdb->iface.deinit(passdb);

	/* make sure passdb isn't accessed again */
	passdb->iface = passdb_iface_deinit;
}

const char *
passdb_result_to_string(enum passdb_result result)
{
	switch (result) {
	case PASSDB_RESULT_INTERNAL_FAILURE:
		return "internal_failure";
	case PASSDB_RESULT_SCHEME_NOT_AVAILABLE:
		return "scheme_not_available";
	case PASSDB_RESULT_USER_UNKNOWN:
		return "user_unknown";
	case PASSDB_RESULT_USER_DISABLED:
		return "user_disabled";
	case PASSDB_RESULT_PASS_EXPIRED:
		return "pass_expired";
	case PASSDB_RESULT_NEXT:
		return "next";
	case PASSDB_RESULT_PASSWORD_MISMATCH:
		return "password_mismatch";
	case PASSDB_RESULT_OK:
		return "ok";
	}
	i_unreached();
}

extern struct passdb_module_interface passdb_passwd;
extern struct passdb_module_interface passdb_bsdauth;
#ifdef HAVE_LUA
extern struct passdb_module_interface passdb_lua;
#endif
extern struct passdb_module_interface passdb_passwd_file;
extern struct passdb_module_interface passdb_pam;
extern struct passdb_module_interface passdb_ldap;
extern struct passdb_module_interface passdb_sql;
extern struct passdb_module_interface passdb_static;
extern struct passdb_module_interface passdb_oauth2;

void passdbs_init(void)
{
	i_array_init(&passdb_interfaces, 16);
	i_array_init(&passdb_modules, 16);
	passdb_register_module(&passdb_passwd);
	passdb_register_module(&passdb_bsdauth);
#ifdef HAVE_LUA
	passdb_register_module(&passdb_lua);
#endif
	passdb_register_module(&passdb_passwd_file);
	passdb_register_module(&passdb_pam);
	passdb_register_module(&passdb_ldap);
	passdb_register_module(&passdb_sql);
	passdb_register_module(&passdb_static);
	passdb_register_module(&passdb_oauth2);
}

void passdbs_deinit(void)
{
	array_free(&passdb_modules);
	array_free(&passdb_interfaces);
}
