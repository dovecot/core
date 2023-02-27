/* Copyright (c) 2004-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "password-scheme.h"
#include "randgen.h"
#include "doveadm.h"
#include "askpass.h"
#include "module-dir.h"

#include <ctype.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>

#define DEFAULT_SCHEME "CRYPT"

static struct module *modules = NULL;

static void cmd_pw(struct doveadm_cmd_context *cctx)
{
	const char *hash = NULL;
	const char *scheme = NULL;
	const char *plaintext = NULL;
	const char *test_hash = NULL;
	bool list_schemes = FALSE;
	struct module_dir_load_settings mod_set;
	struct password_generate_params gen_params;
	i_zero(&gen_params);

	password_schemes_init();
	password_schemes_allow_weak(TRUE);

	i_zero(&mod_set);
	mod_set.abi_version = DOVECOT_ABI_VERSION;
	mod_set.require_init_funcs = TRUE;
	mod_set.ignore_dlopen_errors = TRUE;
	mod_set.debug = doveadm_debug;

	modules = module_dir_load_missing(modules, AUTH_MODULE_DIR, NULL, &mod_set);
	module_dir_init(modules);

	(void)doveadm_cmd_param_bool(cctx, "list", &list_schemes);
	(void)doveadm_cmd_param_str(cctx, "plaintext", &plaintext);
	(void)doveadm_cmd_param_uint32(cctx, "rounds", &gen_params.rounds);
	(void)doveadm_cmd_param_str(cctx, "scheme", &scheme);
	(void)doveadm_cmd_param_str(cctx, "user", &gen_params.user);
	bool reverse_verify =
		doveadm_cmd_param_flag(cctx, "reverse-verify") ||
		doveadm_cmd_param_str(cctx, "test-hash", &test_hash);

	if (list_schemes) {
		ARRAY_TYPE(password_scheme_p) arr;
		const struct password_scheme *const *schemes;
		unsigned int i, count;
		t_array_init(&arr, 30);
		password_schemes_get(&arr);
		schemes = array_get(&arr, &count);
		for (i = 0; i < count; i++)
			printf("%s ", schemes[i]->name);
		printf("\n");
		module_dir_unload(&modules);
		password_schemes_deinit();
		return;
	}

	scheme = scheme == NULL ? DEFAULT_SCHEME : t_str_ucase(scheme);

	if (test_hash != NULL && plaintext == NULL)
		plaintext = t_askpass("Enter password to verify: ");
	while (plaintext == NULL) {
		const char *check;
		static int lives = 3;

		plaintext = t_askpass("Enter new password: ");
		check = t_askpass("Retype new password: ");
		if (strcmp(plaintext, check) != 0) {
			e_error(cctx->event, "Passwords don't match!");
			if (--lives == 0)
				lib_exit(1);
			plaintext = NULL;
		}
	}

	password_schemes_allow_weak(TRUE);

	if (!password_generate_encoded(plaintext, &gen_params, scheme, &hash))
		i_fatal("Unknown scheme: %s", scheme);
	if (reverse_verify) {
		const unsigned char *raw_password;
		size_t size;
		const char *error;

		if (test_hash != NULL) {
			scheme = password_get_scheme(&test_hash);
			if (scheme == NULL)
				i_fatal("Missing {scheme} prefix from hash");
			hash = test_hash;
		}

		if (password_decode(hash, scheme, &raw_password, &size,
				    &error) <= 0)
			i_fatal("reverse decode check failed: %s", error);

		if (password_verify(plaintext, &gen_params, scheme,
				    raw_password, size, &error) <= 0) {
			i_fatal("reverse password verification check failed: %s",
				error);
		}

		printf("{%s}%s (verified)\n", scheme, hash);
	} else {
		printf("{%s}%s\n", scheme, hash);
	}

	module_dir_unload(&modules);
	password_schemes_deinit();
}

struct doveadm_cmd_ver2 doveadm_cmd_pw = {
	.name = "pw",
	.cmd = cmd_pw,
	.usage = "[-l] [-p plaintext] [-r rounds] [-s scheme] [-t hash] [-u user] [-V]",
DOVEADM_CMD_PARAMS_START
DOVEADM_CMD_PARAM('l', "list", CMD_PARAM_BOOL, 0)
DOVEADM_CMD_PARAM('p', "plaintext", CMD_PARAM_STR, 0)
DOVEADM_CMD_PARAM('r', "rounds", CMD_PARAM_INT64, CMD_PARAM_FLAG_UNSIGNED)
DOVEADM_CMD_PARAM('s', "scheme", CMD_PARAM_STR, 0)
DOVEADM_CMD_PARAM('t', "test-hash", CMD_PARAM_STR, 0)
DOVEADM_CMD_PARAM('u', "user", CMD_PARAM_STR, 0)
DOVEADM_CMD_PARAM('V', "reverse-verify", CMD_PARAM_BOOL, 0)
DOVEADM_CMD_PARAMS_END
};
