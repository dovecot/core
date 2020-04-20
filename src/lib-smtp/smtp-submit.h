#ifndef SMTP_SUBMIT_H
#define SMTP_SUBMIT_H

#include "smtp-submit-settings.h"

struct ssl_iostream_settings;
struct smtp_address;
struct smtp_submit_settings;
struct smtp_submit_session;
struct smtp_submit;

struct smtp_submit_input {
	/* SSL settings */
	const struct ssl_iostream_settings *ssl;

	/* Event to use as parent for the submit event */
	struct event *event_parent;

	/* Allow running sendmail as root */
	bool allow_root:1;
};

struct smtp_submit_result {
	/* 1 on success,
	   0 on permanent failure (e.g. invalid destination),
	  -1 on temporary failure */
	int status;

	const char *error;
};

typedef void
smtp_submit_callback_t(const struct smtp_submit_result *result,
		       void *context);

/* Use submit session to reuse resources (e.g. SMTP connections) between
   submissions (FIXME: actually implement this) */
struct smtp_submit_session *
smtp_submit_session_init(const struct smtp_submit_input *input,
			 const struct smtp_submit_settings *set);
void smtp_submit_session_deinit(struct smtp_submit_session **_session);

struct smtp_submit *
smtp_submit_init(struct smtp_submit_session *session,
		 const struct smtp_address *mail_from);
struct smtp_submit *
smtp_submit_init_simple(const struct smtp_submit_input *input,
			const struct smtp_submit_settings *set,
			const struct smtp_address *mail_from) ATTR_NULL(2);
void smtp_submit_deinit(struct smtp_submit **_submit);

/* Add a new recipient */
void smtp_submit_add_rcpt(struct smtp_submit *subm,
	const struct smtp_address *rcpt_to);
/* Get an output stream where the message can be written to. The recipients
   must already be added before calling this. */
struct ostream *smtp_submit_send(struct smtp_submit *subm);

/* Submit the message. Callback is called once the message submission
   finishes. */
void smtp_submit_run_async(struct smtp_submit *subm,
			   smtp_submit_callback_t *callback, void *context);
#define smtp_submit_run_async(subm, callback, context) \
	smtp_submit_run_async(subm, \
		(smtp_submit_callback_t*)callback, \
		(char*)context - CALLBACK_TYPECHECK(callback, \
			void (*)(const struct smtp_submit_result *result, typeof(context))))

/* Returns 1 on success, 0 on permanent failure (e.g. invalid destination),
   -1 on temporary failure. */
int smtp_submit_run(struct smtp_submit *subm, const char **error_r);

#endif
