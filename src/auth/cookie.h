#ifndef __COOKIE_H
#define __COOKIE_H

#include "auth-interface.h"

struct cookie_data {
	unsigned int login_pid;
	unsigned char cookie[AUTH_COOKIE_SIZE];

	/* continue authentication */
	void (*auth_continue)(struct cookie_data *cookie,
			      struct auth_continued_request_data *request,
			      const unsigned char *data,
			      auth_callback_t callback, void *context);

	/* fills reply from cookie, returns TRUE if successful */
	int (*auth_fill_reply)(struct cookie_data *cookie,
			       struct auth_cookie_reply_data *reply);

	/* Free all data related to cookie */
	void (*free)(struct cookie_data *cookie);

	void *context;
};

/* data->cookie is filled */
void cookie_add(struct cookie_data *data);
/* Looks up the cookie */
struct cookie_data *cookie_lookup(unsigned char cookie[AUTH_COOKIE_SIZE]);
/* Removes and frees the cookie */
void cookie_remove(unsigned char cookie[AUTH_COOKIE_SIZE]);
/* Looks up the cookie and removes it, you have to free the returned data. */
struct cookie_data *
cookie_lookup_and_remove(unsigned int login_pid,
			 unsigned char cookie[AUTH_COOKIE_SIZE]);

/* Remove all cookies created by a login process. */
void cookies_remove_login_pid(unsigned int login_pid);

void cookies_init(void);
void cookies_deinit(void);

#endif
