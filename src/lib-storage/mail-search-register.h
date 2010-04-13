#ifndef MAIL_SEARCH_REGISTER_H
#define MAIL_SEARCH_REGISTER_H

struct imap_arg;
struct mail_search_arg;
struct mail_search_build_context;

struct mail_search_register_arg {
	const char *key;

	/* read wanted parameters from imap_arg, returns parsed arg or NULL if
	   error. error message is set to ctx. */
	struct mail_search_arg *
		(*build)(struct mail_search_build_context *ctx,
			 const struct imap_arg **imap_args);
};

typedef struct mail_search_arg *
mail_search_register_fallback_t(struct mail_search_build_context *ctx,
				const char *key,
				const struct imap_arg **imap_args);

struct mail_search_register *mail_search_register_init(void);
void mail_search_register_deinit(struct mail_search_register **reg);

void mail_search_register_add(struct mail_search_register *reg,
			      const struct mail_search_register_arg *arg,
			      unsigned int count);
/* Register a fallback handler. It's responsible for giving also the
   "unknown key" error. */
void mail_search_register_fallback(struct mail_search_register *reg,
				   mail_search_register_fallback_t *fallback);

/* Find key's registered arg, or NULL if not found. */
const struct mail_search_register_arg *
mail_search_register_find(struct mail_search_register *reg, const char *key);
/* Get registered fallback arg. Returns FALSE if fallback hasn't been
   registered. */
bool mail_search_register_get_fallback(struct mail_search_register *reg,
				       mail_search_register_fallback_t **fallback_r);

struct mail_search_register *mail_search_register_init_imap(void);

#endif
