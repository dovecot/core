#ifndef SMTP_SUBMIT_H
#define SMTP_SUBMIT_H

struct smtp_submit * ATTR_NULL(3)
smtp_submit_init(const struct lda_settings *set, const char *return_path);
/* Add a new recipient */
void smtp_submit_add_rcpt(struct smtp_submit *subm, const char *address);
/* Get an output stream where the message can be written to. The recipients
   must already be added before calling this. */
struct ostream *smtp_submit_send(struct smtp_submit *subm);
void smtp_submit_abort(struct smtp_submit **_subm);
/* Returns 1 on success, 0 on permanent failure (e.g. invalid destination),
   -1 on temporary failure. */
int smtp_submit_deinit(struct smtp_submit *subm, const char **error_r);
/* Same as smtp_submit_deinit(), but timeout after given number of seconds. */
int smtp_submit_deinit_timeout(struct smtp_submit *subm,
			       unsigned int timeout_secs, const char **error_r);
#endif
