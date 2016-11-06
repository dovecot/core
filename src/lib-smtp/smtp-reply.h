#ifndef SMTP_REPLY_H
#define SMTP_REPLY_H

struct smtp_reply_enhanced_code {
	/* x:class, y:subject, z:detail;
	   x==0 means no enhanced code present
	   x==9 means invalid/missing enhanced code in reply
	 */
	unsigned int x, y, z;
};

struct smtp_reply {
	unsigned int status;

	struct smtp_reply_enhanced_code enhanced_code;

	const char *const *text_lines;
};

#define SMTP_REPLY_ENH_CODE(x, y, z) \
	(const struct smtp_reply_enhanced_code){(x), (y), (z)}
#define SMTP_REPLY_ENH_CODE_NONE SMTP_REPLY_ENH_CODE(0, 0, 0)

static inline bool
smtp_reply_has_enhanced_code(const struct smtp_reply *reply)
{
	return reply->enhanced_code.x > 1 && reply->enhanced_code.x < 6;
}

static inline bool
smtp_reply_is_success(const struct smtp_reply *reply)
{
	return ((reply->status / 100) == 2);
}

static inline bool
smtp_reply_is_remote(const struct smtp_reply *reply)
{
	return (reply->status >= 200 && reply->status < 560);
}

static inline bool
smtp_reply_is_temp_fail(const struct smtp_reply *reply)
{
	return ((reply->status / 100) == 4);
}

void smtp_reply_init(struct smtp_reply *reply, unsigned int status,
	const char *text);
void smtp_reply_printf(struct smtp_reply *reply, unsigned int status,
	const char *format, ...) ATTR_FORMAT(3, 4);

const char *
smtp_reply_get_enh_code(const struct smtp_reply *reply);
void smtp_reply_write(string_t *out, const struct smtp_reply *reply);
const char *smtp_reply_log(const struct smtp_reply *reply);

void smtp_reply_copy(pool_t pool, struct smtp_reply *dst,
	const struct smtp_reply *src);
struct smtp_reply *smtp_reply_clone(pool_t pool,
	const struct smtp_reply *src);

#endif
