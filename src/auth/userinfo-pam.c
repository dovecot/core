/*
   Based on auth_pam.c from popa3d by Solar Designer <solar@openwall.com>.

   You're allowed to do whatever you like with this software (including
   re-distribution in source and/or binary form, with or without
   modification), provided that credit is given where it is due and any
   modified versions are marked as such.  There's absolutely no warranty.
*/

#define _XOPEN_SOURCE 4
#define _XOPEN_SOURCE_EXTENDED
#define _XPG4_2

#include "common.h"

#ifdef USERINFO_PAM

#include "userinfo.h"
#include "userinfo-passwd.h"

#include <stdlib.h>
#include <unistd.h>
#include <shadow.h>

#include <security/pam_appl.h>

#if defined(__sun__) && !defined(LINUX_PAM)
#  define linux_const			/* Sun's PAM doesn't use const here */
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

typedef struct {
	const char *user;
	const char *pass;
} pam_userpass_t;

static pam_handle_t *pamh;
static pam_userpass_t userpass;

static int pam_userpass_conv(int num_msg, linux_const struct pam_message **msg,
	struct pam_response **resp, void *appdata_ptr)
{
	pam_userpass_t *userpass = (pam_userpass_t *)appdata_ptr;
#ifdef AUTH_PAM_USERPASS
	pamc_bp_t prompt;
	const char *input;
	char *output;
	char flags;

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

	prompt = NULL;
	PAM_BP_RENEW(&prompt, PAM_BPC_DONE,
		strlen(userpass->user) + 1 + strlen(userpass->pass));
	output = PAM_BP_WDATA(prompt);

	strcpy(output, userpass->user);
	output += strlen(output) + 1;
	memcpy(output, userpass->pass, strlen(userpass->pass));

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
				memset((*resp)[i].resp, 0,
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

static int pam_verify_plain(const char *user, const char *password,
			    AuthCookieReplyData *reply)
{
	struct passwd *pw;
	char *item;
	int status;

	userpass.user = user;
	userpass.pass = password;

	if ((status = pam_authenticate(pamh, 0)) != PAM_SUCCESS) {
		if (status == PAM_ABORT)
			i_fatal("pam_authenticate() requested abort");
		return FALSE;
	}

	if ((status = pam_acct_mgmt(pamh, 0)) != PAM_SUCCESS) {
		if (status == PAM_ABORT)
			i_fatal("pam_acct_mgmt() requested abort");
		return FALSE;
	}

	status = pam_get_item(pamh, PAM_USER, (pam_item_t *)&item);
	if (status != PAM_SUCCESS) {
		if (status == PAM_ABORT)
			i_fatal("pam_get_item() requested abort");
		return FALSE;
	}

	/* password ok, save the user info */
	pw = getpwnam(user);
	if (pw == NULL)
		return FALSE;

	memset(pw->pw_passwd, 0, strlen(pw->pw_passwd));
	passwd_fill_cookie_reply(pw, reply);
	return TRUE;
}

static void pam_init(const char *args)
{
	static struct pam_conv conv = {
		pam_userpass_conv,
		&userpass
	};
	const char *service_name;
	int status;

	service_name = *args != '\0' ? args : "imap";
	status = pam_start(service_name, NULL, &conv, &pamh);
	if (status != PAM_SUCCESS)
		i_fatal("pam_start() failed: %s", pam_strerror(pamh, status));
}

static void pam_deinit(void)
{
	(void)pam_end(pamh, PAM_SUCCESS);
}

UserInfoModule userinfo_pam = {
	pam_init,
	pam_deinit,

	pam_verify_plain,
	NULL
};

#endif
