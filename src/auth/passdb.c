/* Copyright (c) 2002-2011 Dovecot authors, see the included COPYING file */

#include "auth-common.h"
#include "array.h"
#include "password-scheme.h"
#include "auth-worker-server.h"
#include "passdb-template.h"
#include "passdb.h"

#include <stdlib.h>

static ARRAY_DEFINE(passdb_interfaces, struct passdb_module_interface *);
static ARRAY_DEFINE(passdb_modules, struct passdb_module *);

static const struct passdb_module_interface passdb_iface_deinit = {
	.name = "deinit"
};

static struct passdb_module_interface *passdb_interface_find(const char *name)
{
	struct passdb_module_interface *const *ifaces;

	array_foreach(&passdb_interfaces, ifaces) {
		struct passdb_module_interface *iface = *ifaces;

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
	array_append(&passdb_interfaces, &iface, 1);
}

void passdb_unregister_module(struct passdb_module_interface *iface)
{
	struct passdb_module_interface *const *ifaces;
	unsigned int idx;

	array_foreach(&passdb_interfaces, ifaces) {
		if (*ifaces == iface) {
			idx = array_foreach_idx(&passdb_interfaces, ifaces);
			array_delete(&passdb_interfaces, idx, 1);
			return;
		}
	}
	i_panic("passdb_unregister_module(%s): Not registered", iface->name);
}

bool passdb_get_credentials(struct auth_request *auth_request,
			    const char *input, const char *input_scheme,
			    const unsigned char **credentials_r, size_t *size_r)
{
	const char *wanted_scheme = auth_request->credentials_scheme;
	const char *plaintext, *username, *error;
	int ret;

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
			auth_request_log_error(auth_request, "password",
				"Password data is not valid for scheme %s: %s",
				input_scheme, error);
		} else {
			auth_request_log_error(auth_request, "password",
				"Unknown scheme %s", input_scheme);
		}
		return FALSE;
	}

	if (*wanted_scheme == '\0') {
		/* anything goes. change the credentials_scheme to what we
		   actually got, so blocking passdbs work. */
		auth_request->credentials_scheme =
			p_strdup(auth_request->pool, input_scheme);
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
			auth_request_log_info(auth_request, "password",
					      "%s", error);
			return FALSE;
		}

		/* we can generate anything out of plaintext passwords */
		plaintext = t_strndup(*credentials_r, *size_r);
		username = auth_request->original_username;
		if (!auth_request->domain_is_realm &&
		    strchr(username, '@') != NULL) {
			/* domain must not be used as realm. add the @realm. */
			username = t_strconcat(username, "@",
					       auth_request->realm, NULL);
		}
		if (auth_request->set->debug_passwords) {
			auth_request_log_debug(auth_request, "password",
				"Generating %s from user '%s', password '%s'",
				wanted_scheme, username, plaintext);
		}
		if (!password_generate(plaintext, username,
				       wanted_scheme, credentials_r, size_r)) {
			auth_request_log_error(auth_request, "password",
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
	}

	if (password != NULL) {
		if (!passdb_get_credentials(auth_request, password, scheme,
					    &credentials, &size))
			result = PASSDB_RESULT_SCHEME_NOT_AVAILABLE;
	} else if (*auth_request->credentials_scheme == '\0') {
		/* We're doing a passdb lookup (not authenticating).
		   Pass through a NULL password without an error. */
	} else {
		auth_request_log_info(auth_request, "password",
			"Requested %s scheme, but we have a NULL password",
			auth_request->credentials_scheme);
		result = PASSDB_RESULT_SCHEME_NOT_AVAILABLE;
	}

	callback(result, credentials, size, auth_request);
}

static struct passdb_module *
passdb_find(const char *driver, const char *args, unsigned int *idx_r)
{
	struct passdb_module *const *passdbs;
	unsigned int i, count;

	passdbs = array_get(&passdb_modules, &count);
	for (i = 0; i < count; i++) {
		if (strcmp(passdbs[i]->iface.name, driver) == 0 &&
		    strcmp(passdbs[i]->args, args) == 0) {
			*idx_r = i;
			return passdbs[i];
		}
	}
	return NULL;
}

struct passdb_module *
passdb_preinit(pool_t pool, const struct auth_passdb_settings *set)
{
	static unsigned int auth_passdb_id = 0;
	struct passdb_module_interface *iface;
	struct passdb_module *passdb;
	unsigned int idx;

	iface = passdb_interface_find(set->driver);
	if (iface == NULL)
		i_fatal("Unknown passdb driver '%s'", set->driver);
	if (iface->verify_plain == NULL) {
		i_fatal("Support not compiled in for passdb driver '%s'",
			set->driver);
	}
	if (iface->preinit == NULL && iface->init == NULL &&
	    *set->args != '\0') {
		i_fatal("passdb %s: No args are supported: %s",
			set->driver, set->args);
	}

	passdb = passdb_find(set->driver, set->args, &idx);
	if (passdb != NULL)
		return passdb;

	if (iface->preinit == NULL)
		passdb = p_new(pool, struct passdb_module, 1);
	else
		passdb = iface->preinit(pool, set->args);
	passdb->id = ++auth_passdb_id;
	passdb->iface = *iface;
	passdb->args = p_strdup(pool, set->args);

	passdb->default_fields_tmpl =
		passdb_template_build(pool, set->default_fields);
	passdb->override_fields_tmpl =
		passdb_template_build(pool, set->override_fields);

	array_append(&passdb_modules, &passdb, 1);
	return passdb;
}

void passdb_init(struct passdb_module *passdb)
{
	if (passdb->iface.init != NULL && passdb->init_refcount == 0)
		passdb->iface.init(passdb);
	passdb->init_refcount++;

	i_assert(passdb->default_pass_scheme != NULL ||
		 passdb->cache_key == NULL);
}

void passdb_deinit(struct passdb_module *passdb)
{
	unsigned int idx;

	i_assert(passdb->init_refcount > 0);

	if (--passdb->init_refcount > 0)
		return;

	if (passdb_find(passdb->iface.name, passdb->args, &idx) == NULL)
		i_unreached();
	array_delete(&passdb_modules, idx, 1);

	if (passdb->iface.deinit != NULL)
		passdb->iface.deinit(passdb);

	/* make sure passdb isn't accessed again */
	passdb->iface = passdb_iface_deinit;
}

void passdbs_generate_md5(unsigned char md5[MD5_RESULTLEN])
{
	struct md5_context ctx;
	struct passdb_module *const *passdbs;
	unsigned int i, count;

	md5_init(&ctx);
	passdbs = array_get(&passdb_modules, &count);
	for (i = 0; i < count; i++) {
		md5_update(&ctx, &passdbs[i]->id, sizeof(passdbs[i]->id));
		md5_update(&ctx, passdbs[i]->iface.name,
			   strlen(passdbs[i]->iface.name));
		md5_update(&ctx, passdbs[i]->args, strlen(passdbs[i]->args));
	}
	md5_final(&ctx, md5);
}

extern struct passdb_module_interface passdb_passwd;
extern struct passdb_module_interface passdb_bsdauth;
extern struct passdb_module_interface passdb_shadow;
extern struct passdb_module_interface passdb_passwd_file;
extern struct passdb_module_interface passdb_pam;
extern struct passdb_module_interface passdb_checkpassword;
extern struct passdb_module_interface passdb_vpopmail;
extern struct passdb_module_interface passdb_ldap;
extern struct passdb_module_interface passdb_sql;
extern struct passdb_module_interface passdb_sia;
extern struct passdb_module_interface passdb_static;

void passdbs_init(void)
{
	i_array_init(&passdb_interfaces, 16);
	i_array_init(&passdb_modules, 16);
	passdb_register_module(&passdb_passwd);
	passdb_register_module(&passdb_bsdauth);
	passdb_register_module(&passdb_passwd_file);
	passdb_register_module(&passdb_pam);
	passdb_register_module(&passdb_checkpassword);
	passdb_register_module(&passdb_shadow);
	passdb_register_module(&passdb_vpopmail);
	passdb_register_module(&passdb_ldap);
	passdb_register_module(&passdb_sql);
	passdb_register_module(&passdb_sia);
	passdb_register_module(&passdb_static);
}

void passdbs_deinit(void)
{
	array_free(&passdb_modules);
	array_free(&passdb_interfaces);
}
