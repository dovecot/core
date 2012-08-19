#ifndef DOVEADM_WHO_H
#define DOVEADM_WHO_H

struct who_line {
	const char *username;
	const char *service;
	struct ip_addr ip;
	pid_t pid;
	unsigned int refcount;
};


struct who_filter {
	const char *username;
	struct ip_addr net_ip;
	unsigned int net_bits;
};

struct who_context {
	const char *anvil_path;
	struct who_filter filter;

	pool_t pool;
	HASH_TABLE(struct who_user *, struct who_user *) users;
};

typedef void who_callback_t(struct who_context *ctx,
			    const struct who_line *line);

void who_parse_args(struct who_context *ctx, char **args);

void who_lookup(struct who_context *ctx, who_callback_t *callback);

bool who_line_filter_match(const struct who_line *line,
			   const struct who_filter *filter);

#endif /* DOVEADM_WHO_H */
