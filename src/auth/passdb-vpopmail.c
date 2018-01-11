/* Copyright (c) 2002-2018 Dovecot authors, see the included COPYING file */

/* Thanks to Courier-IMAP for showing how the vpopmail API should be used */

#include "auth-common.h"
#include "passdb.h"

#ifdef PASSDB_VPOPMAIL

#include "safe-memset.h"
#include "password-scheme.h"
#include "auth-cache.h"

#include "userdb-vpopmail.h"


#define VPOPMAIL_DEFAULT_PASS_SCHEME "CRYPT"

/* pw_flags was added in vpopmail 5.4, olders use pw_gid field */
#ifndef VQPASSWD_HAS_PW_FLAGS
#  define pw_flags pw_gid
#endif

struct vpopmail_passdb_module {
	struct passdb_module module;

	struct ip_addr webmail_ip;
};

static bool vpopmail_is_disabled(struct auth_request *request,
				 const struct vqpasswd *vpw)
{
        struct passdb_module *_module = request->passdb->passdb;
	struct vpopmail_passdb_module *module =
		(struct vpopmail_passdb_module *)_module;

	if (strcasecmp(request->service, "IMAP") == 0) {
		if ((vpw->pw_flags & NO_IMAP) != 0) {
			/* IMAP from webmail IP may still be allowed */
			if (!net_ip_compare(&module->webmail_ip,
					    &request->remote_ip))
				return TRUE;
		}
		if ((vpw->pw_flags & NO_WEBMAIL) != 0) {
			if (net_ip_compare(&module->webmail_ip,
					   &request->remote_ip))
				return TRUE;
		}
	}
	if ((vpw->pw_flags & NO_POP) != 0 &&
	    strcasecmp(request->service, "POP3") == 0)
		return TRUE;
	if ((vpw->pw_flags & NO_SMTP) != 0 &&
	    strcasecmp(request->service, "SMTP") == 0)
		return TRUE;
	return FALSE;
}

static char *
vpopmail_password_lookup(struct auth_request *auth_request, bool *cleartext,
			 enum passdb_result *result_r)
{
	char vpop_user[VPOPMAIL_LIMIT], vpop_domain[VPOPMAIL_LIMIT];
	struct vqpasswd *vpw;
	char *password;

	vpw = vpopmail_lookup_vqp(auth_request, vpop_user, vpop_domain);
	if (vpw == NULL) {
		*result_r = PASSDB_RESULT_USER_UNKNOWN;
		return NULL;
	}

	if (vpopmail_is_disabled(auth_request, vpw)) {
		auth_request_log_info(auth_request, AUTH_SUBSYS_DB,
				      "%s disabled in vpopmail for this user",
				      auth_request->service);
		password = NULL;
		*result_r = PASSDB_RESULT_USER_DISABLED;
	} else {
		if (vpw->pw_clear_passwd != NULL &&
		    *vpw->pw_clear_passwd != '\0') {
			password = t_strdup_noconst(vpw->pw_clear_passwd);
			*cleartext = TRUE;
		} else if (!*cleartext)
			password = t_strdup_noconst(vpw->pw_passwd);
		else
			password = NULL;
		*result_r = password != NULL ? PASSDB_RESULT_OK :
			PASSDB_RESULT_SCHEME_NOT_AVAILABLE;
	}

	safe_memset(vpw->pw_passwd, 0, strlen(vpw->pw_passwd));
	if (vpw->pw_clear_passwd != NULL) {
		safe_memset(vpw->pw_clear_passwd, 0,
			    strlen(vpw->pw_clear_passwd));
	}

	return password;
}

static void vpopmail_lookup_credentials(struct auth_request *request,
					lookup_credentials_callback_t *callback)
{
	enum passdb_result result;
	char *password;
	bool cleartext = TRUE;

	password = vpopmail_password_lookup(request, &cleartext, &result);
	if (password == NULL) {
		callback(result, NULL, 0, request);
		return;
	}
	
	passdb_handle_credentials(PASSDB_RESULT_OK, password, "CLEARTEXT",
				  callback, request);
	safe_memset(password, 0, strlen(password));
}

static void
vpopmail_verify_plain(struct auth_request *request, const char *password,
		      verify_plain_callback_t *callback)
{
	enum passdb_result result;
	const char *scheme, *tmp_pass;
	char *crypted_pass;
	bool cleartext = FALSE;
	int ret;

	crypted_pass = vpopmail_password_lookup(request, &cleartext, &result);
	if (crypted_pass == NULL) {
		callback(result, request);
		return;
	}
	tmp_pass = crypted_pass;

	if (cleartext)
		scheme = "CLEARTEXT";
	else {
		scheme = password_get_scheme(&tmp_pass);
		if (scheme == NULL)
			scheme = request->passdb->passdb->default_pass_scheme;
	}

	ret = auth_request_password_verify(request, password, tmp_pass,
					   scheme, AUTH_SUBSYS_DB);
	safe_memset(crypted_pass, 0, strlen(crypted_pass));

	if (ret <= 0) {
		callback(PASSDB_RESULT_PASSWORD_MISMATCH, request);
		return;
	}

#ifdef POP_AUTH_OPEN_RELAY
	if (strcasecmp(request->service, "POP3") == 0 ||
	    strcasecmp(request->service, "IMAP") == 0) {
		const char *host = net_ip2addr(&request->remote_ip);
		/* vpopmail 5.4 does not understand IPv6 */
		if (host[0] != '\0' && IPADDR_IS_V4(&request->remote_ip)) {
			/* use putenv() directly rather than env_put() which
			   would leak memory every time we got here. use a
			   static buffer for putenv() as SUSv2 requirements
			   would otherwise corrupt our environment later. */
			static char ip_env[256];

			i_snprintf(ip_env, sizeof(ip_env),
				   "TCPREMOTEIP=%s", host);
			putenv(ip_env);
			open_smtp_relay();
		}
	}
#endif

	callback(PASSDB_RESULT_OK, request);
}

static struct passdb_module *
vpopmail_preinit(pool_t pool, const char *args)
{
	static bool vauth_load_initialized = FALSE;
	struct vpopmail_passdb_module *module;
	const char *const *tmp;

	module = p_new(pool, struct vpopmail_passdb_module, 1);
	module->module.default_pass_scheme = VPOPMAIL_DEFAULT_PASS_SCHEME;
	module->module.blocking = TRUE;

	tmp = t_strsplit_spaces(args, " ");
	for (; *tmp != NULL; tmp++) {
		if (str_begins(*tmp, "cache_key=")) {
			module->module.default_cache_key =
				auth_cache_parse_key(pool, *tmp + 10);
		} else if (str_begins(*tmp, "webmail=")) {
			if (net_addr2ip(*tmp + 8, &module->webmail_ip) < 0)
				i_fatal("vpopmail: Invalid webmail IP address");
		} else if (strcmp(*tmp, "blocking=no") == 0) {
			module->module.blocking = FALSE;
		} else {
			i_fatal("passdb vpopmail: Unknown setting: %s", *tmp);
		}
	}
	if (!vauth_load_initialized) {
		vauth_load_initialized = TRUE;
		if (vauth_open(0) != 0)
			i_fatal("vpopmail: vauth_open() failed");
	}
	return &module->module;
}

static void vpopmail_deinit(struct passdb_module *module ATTR_UNUSED)
{
	vclose();
}

struct passdb_module_interface passdb_vpopmail = {
	"vpopmail",

	vpopmail_preinit,
	NULL,
	vpopmail_deinit,

	vpopmail_verify_plain,
	vpopmail_lookup_credentials,
	NULL
};
#else
struct passdb_module_interface passdb_vpopmail = {
	.name = "vpopmail"
};
#endif
