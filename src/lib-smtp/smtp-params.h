#ifndef SMTP_PARAMS_H
#define SMTP_PARAMS_H

#include "array-decl.h"

#include "smtp-common.h"

struct smtp_param;

ARRAY_DEFINE_TYPE(smtp_param, struct smtp_param);

enum smtp_param_mail_body_type {
	SMTP_PARAM_MAIL_BODY_TYPE_UNSPECIFIED = 0,
	SMTP_PARAM_MAIL_BODY_TYPE_7BIT,
	SMTP_PARAM_MAIL_BODY_TYPE_8BITMIME,
	SMTP_PARAM_MAIL_BODY_TYPE_BINARYMIME,
	SMTP_PARAM_MAIL_BODY_TYPE_EXTENSION
};

enum smtp_param_mail_ret {
	SMTP_PARAM_MAIL_RET_UNSPECIFIED = 0,
	SMTP_PARAM_MAIL_RET_HDRS,
	SMTP_PARAM_MAIL_RET_FULL,
};

enum smtp_param_rcpt_notify {
	SMTP_PARAM_RCPT_NOTIFY_UNSPECIFIED = 0x00,
	SMTP_PARAM_RCPT_NOTIFY_SUCCESS   	 = 0x01,
	SMTP_PARAM_RCPT_NOTIFY_FAILURE     = 0x02,
	SMTP_PARAM_RCPT_NOTIFY_DELAY       = 0x04,
	SMTP_PARAM_RCPT_NOTIFY_NEVER       = 0x80
};

struct smtp_param {
	const char *keyword;
	const char *value;
};

struct smtp_params_mail {
	/* AUTH: RFC 4954 */
	const struct smtp_address *auth;
	/* BODY: RFC 6152 */
	struct {
		enum smtp_param_mail_body_type type;
		const char *ext;
	} body;
	/* ENVID: RFC 3461, Section 4.4 */
	const char *envid;
	/* RET: RFC 3461, Section 4.3 */
	enum smtp_param_mail_ret ret;
	/* SIZE: RFC 1870 */
	uoff_t size;
	/* extra parameters */
	ARRAY_TYPE(smtp_param) extra_params;
};

struct smtp_params_rcpt {
	/* ORCPT: RFC 3461, Section 4.2 */
	struct {
		const char *addr_type;
		/* addr_type=rfc822 */
		const struct smtp_address *addr;
		/* raw value */
		const char *addr_raw;
	} orcpt;
	/* NOTIFY: RFC 3461, Section 4.1 */
	enum smtp_param_rcpt_notify notify;
	/* extra parameters */
	ARRAY_TYPE(smtp_param) extra_params;
};

enum smtp_param_parse_error {
	SMTP_PARAM_PARSE_ERROR_BAD_SYNTAX = 0,
	SMTP_PARAM_PARSE_ERROR_NOT_SUPPORTED
};

/*
 * Common
 */

/* parse */

int smtp_param_parse(pool_t pool, const char *text,
		     struct smtp_param *param_r, const char **error_r);

/* manipulate */

void smtp_params_add_one(ARRAY_TYPE(smtp_param) *params, pool_t pool,
			 const char *keyword, const char *value);
bool smtp_params_drop_one(ARRAY_TYPE(smtp_param) *params, const char *keyword,
			  const char **value_r);

/* write */

void smtp_param_write(string_t *out, const struct smtp_param *param);

/* evaluate */

const struct smtp_param *
smtp_params_get_param(const ARRAY_TYPE(smtp_param) *params,
		      const char *keyword);

/*
 * MAIL parameters
 */

/* parse */

int smtp_params_mail_parse(pool_t pool, const char *args,
			   enum smtp_capability caps,
			   const char *const *param_extensions,
			   const char *const *body_param_extensions,
			   struct smtp_params_mail *params_r,
			   enum smtp_param_parse_error *error_code_r,
			   const char **error_r) ATTR_NULL(4, 5);

/* manipulate */

void smtp_params_mail_copy(pool_t pool, struct smtp_params_mail *dst,
			   const struct smtp_params_mail *src) ATTR_NULL(3);

void smtp_params_mail_add_extra(struct smtp_params_mail *params, pool_t pool,
				const char *keyword, const char *value)
				ATTR_NULL(4);
bool smtp_params_mail_drop_extra(struct smtp_params_mail *params,
				 const char *keyword, const char **value_r)
				 ATTR_NULL(3);

/* write */

void smtp_params_mail_write(string_t *buffer, enum smtp_capability caps,
			    const struct smtp_params_mail *params);

/* evaluate */

const struct smtp_param *
smtp_params_mail_get_extra(const struct smtp_params_mail *params,
			   const char *keyword);

/* events */

void smtp_params_mail_add_to_event(const struct smtp_params_mail *params,
				   struct event *event);

/*
 * RCPT parameters
 */

/* parse */

enum smtp_param_rcpt_parse_flags {
	/* Allow address values without a domain part */
	SMTP_PARAM_RCPT_FLAG_ORCPT_ALLOW_LOCALPART = BIT(0),
};

int smtp_params_rcpt_parse(pool_t pool, const char *args,
			   enum smtp_param_rcpt_parse_flags flags,
			   enum smtp_capability caps,
			   const char *const *param_extensions,
			   struct smtp_params_rcpt *params_r,
			   enum smtp_param_parse_error *error_code_r,
			   const char **error_r) ATTR_NULL(4);

/* manipulate */

void smtp_params_rcpt_copy(pool_t pool, struct smtp_params_rcpt *dst,
			   const struct smtp_params_rcpt *src) ATTR_NULL(3);

void smtp_params_rcpt_add_extra(struct smtp_params_rcpt *params, pool_t pool,
				const char *keyword, const char *value)
				ATTR_NULL(4);
bool smtp_params_rcpt_drop_extra(struct smtp_params_rcpt *params,
				 const char *keyword, const char **value_r)
				 ATTR_NULL(3);

void smtp_params_rcpt_set_orcpt(struct smtp_params_rcpt *params, pool_t pool,
				struct smtp_address *rcpt);

/* write */

void smtp_params_rcpt_write(string_t *buffer, enum smtp_capability caps,
			    const struct smtp_params_rcpt *params);

/* evaluate */

const struct smtp_param *
smtp_params_rcpt_get_extra(const struct smtp_params_rcpt *params,
			   const char *keyword);

bool smtp_params_rcpt_equal(const struct smtp_params_rcpt *params1,
			    const struct smtp_params_rcpt *params2);

static inline bool
smtp_params_rcpt_has_orcpt(const struct smtp_params_rcpt *params)
{
	return (params->orcpt.addr_type != NULL);
}

/* events */

void smtp_params_rcpt_add_to_event(const struct smtp_params_rcpt *params,
				   struct event *event);

#endif
