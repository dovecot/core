/*
   Based on auth_pam.c from popa3d by Solar Designer <solar@openwall.com>.

   You're allowed to do whatever you like with this software (including
   re-distribution in source and/or binary form, with or without
   modification), provided that credit is given where it is due and any
   modified versions are marked as such.  There's absolutely no warranty.
*/

#include "config.h"
#undef HAVE_CONFIG_H

#ifdef PASSDB_PAM

#include "common.h"
#include "passdb.h"
#include "mycrypt.h"
#include "safe-memset.h"

#include <stdlib.h>
#ifdef HAVE_SECURITY_PAM_APPL_H
#  include <security/pam_appl.h>
#elif defined(HAVE_PAM_PAM_APPL_H)
#  include <pam/pam_appl.h>
#endif

#if !defined(_SECURITY_PAM_APPL_H) && !defined(LINUX_PAM)
/* Sun's PAM doesn't use const. we use a bit dirty hack to check it.
   Originally it was just __sun__ check, but HP/UX also uses Sun's PAM
   so I thought this might work better. */
#  define linux_const
#else
#  define linux_const			const
#endif
typedef linux_const void *pam_item_t;

#ifdef AUTH_PAM_USERPASS
#  include <security/pam_client.h>

#  ifndef PAM_BP_RCONTROL
/* Linux-PAM prior to 0.74 */
#    define PAM_BP_RCONTROL	PAM_BP_CONTROL
#    define PAM_BP_WDATA	PAM_BP_DATA
#    define PAM_BP_RDATA	PAM_BP_DATA
#  endif

#  define USERPASS_AGENT_ID		"userpass"
#  define USERPASS_AGENT_ID_LENGTH	8

#  define USERPASS_USER_MASK		0x03
#  define USERPASS_USER_REQUIRED	1
#  define USERPASS_USER_KNOWN		2
#  define USERPASS_USER_FIXED		3
#endif

struct pam_userpass {
	const char *user;
	const char *pass;
};

static char *service_name;

static int pam_userpass_conv(int num_msg, linux_const struct pam_message **msg,
	struct pam_response **resp, void *appdata_ptr)
{
	/* @UNSAFE */
	struct pam_userpass *userpass = (struct pam_userpass *) appdata_ptr;
#ifdef AUTH_PAM_USERPASS
	pamc_bp_t prompt;
	const char *input;
	char *output;
	char flags;
	size_t userlen, passlen;

	if (num_msg != 1 || msg[0]->msg_style != PAM_BINARY_PROMPT)
		return PAM_CONV_ERR;

	prompt = (pamc_bp_t)msg[0]->msg;
	input = PAM_BP_RDATA(prompt);

	if (PAM_BP_RCONTROL(prompt) != PAM_BPC_SELECT ||
	    strncmp(input, USERPASS_AGENT_ID "/", USERPASS_AGENT_ID_LENGTH + 1))
		return PAM_CONV_ERR;

	flags = input[USERPASS_AGENT_ID_LENGTH + 1];
	input += USERPASS_AGENT_ID_LENGTH + 1 + 1;

	if ((flags & USERPASS_USER_MASK) == USERPASS_USER_FIXED &&
	    strcmp(input, userpass->user))
		return PAM_CONV_AGAIN;

	if (!(*resp = malloc(sizeof(struct pam_response))))
		return PAM_CONV_ERR;

	userlen = strlen(userpass->user);
	passlen = strlen(userpass->pass);

	prompt = NULL;
	PAM_BP_RENEW(&prompt, PAM_BPC_DONE, userlen + 1 + passlen);
	output = PAM_BP_WDATA(prompt);

	memcpy(output, userpass->user, userlen + 1);
	memcpy(output + userlen + 1, userpass->pass, passlen);

	(*resp)[0].resp_retcode = 0;
	(*resp)[0].resp = (char *)prompt;
#else
	char *string;
	int i;

	if (!(*resp = malloc(num_msg * sizeof(struct pam_response))))
		return PAM_CONV_ERR;

	for (i = 0; i < num_msg; i++) {
		switch (msg[i]->msg_style) {
		case PAM_PROMPT_ECHO_ON:
			string = strdup(userpass->user);
			if (string == NULL)
				i_fatal("Out of memory");
			break;
		case PAM_PROMPT_ECHO_OFF:
			string = strdup(userpass->pass);
			if (string == NULL)
				i_fatal("Out of memory");
			break;
		case PAM_ERROR_MSG:
		case PAM_TEXT_INFO:
			string = NULL;
			break;
		default:
			while (--i >= 0) {
				if ((*resp)[i].resp == NULL)
					continue;
				safe_memset((*resp)[i].resp, 0,
					    strlen((*resp)[i].resp));
				free((*resp)[i].resp);
				(*resp)[i].resp = NULL;
			}

			free(*resp);
			*resp = NULL;

			return PAM_CONV_ERR;
		}

		(*resp)[i].resp_retcode = PAM_SUCCESS;
		(*resp)[i].resp = string;
	}
#endif

	return PAM_SUCCESS;
}

static int pam_auth(pam_handle_t *pamh, const char *user)
{
	char *item;
	int status;

	if ((status = pam_authenticate(pamh, 0)) != PAM_SUCCESS) {
		if (verbose) {
			i_info("PAM: pam_authenticate(%s) failed: %s",
			       user, pam_strerror(pamh, status));
		}
		return status;
	}

#ifdef HAVE_PAM_SETCRED
	if ((status = pam_setcred(pamh, PAM_ESTABLISH_CRED)) != PAM_SUCCESS) {
		if (verbose) {
			i_info("PAM: pam_setcred(%s) failed: %s",
			       user, pam_strerror(pamh, status));
		}
		return status;
	}
#endif

	if ((status = pam_acct_mgmt(pamh, 0)) != PAM_SUCCESS) {
		if (verbose) {
			i_info("PAM: pam_acct_mgmt(%s) failed: %s",
			       user, pam_strerror(pamh, status));
		}
		return status;
	}

	status = pam_get_item(pamh, PAM_USER, (linux_const void **)&item);
	if (status != PAM_SUCCESS) {
		if (verbose) {
			i_info("PAM: pam_get_item(%s) failed: %s",
			       user, pam_strerror(pamh, status));
		}
		return status;
	}

	return PAM_SUCCESS;
}

static enum passdb_result
pam_verify_plain(const char *user, const char *realm, const char *password)
{
	pam_handle_t *pamh;
	struct pam_userpass userpass;
	struct pam_conv conv;
	int status, status2;

	if (realm != NULL)
		user = t_strconcat(user, "@", realm, NULL);

	conv.conv = pam_userpass_conv;
	conv.appdata_ptr = &userpass;

	userpass.user = user;
	userpass.pass = password;

	status = pam_start(service_name, user, &conv, &pamh);
	if (status != PAM_SUCCESS) {
		if (verbose) {
			i_info("PAM: pam_start(%s) failed: %s",
			       user, pam_strerror(pamh, status));
		}
		return PASSDB_RESULT_INTERNAL_FAILURE;
	}

	status = pam_auth(pamh, user);
	if ((status2 = pam_end(pamh, status)) != PAM_SUCCESS) {
		i_error("pam_end(%s) failed: %s",
			user, pam_strerror(pamh, status2));
		return PASSDB_RESULT_INTERNAL_FAILURE;
	}

	/* FIXME: check for PASSDB_RESULT_UNKNOWN_USER somehow */
	return status == PAM_SUCCESS ? PASSDB_RESULT_OK :
		PASSDB_RESULT_PASSWORD_MISMATCH;
}

static void pam_init(const char *args)
{
	service_name = i_strdup(*args != '\0' ? args : "imap");
}

static void pam_deinit(void)
{
	i_free(service_name);
}

struct passdb_module passdb_pam = {
	pam_init,
	pam_deinit,

	pam_verify_plain,
	NULL
};

#endif
