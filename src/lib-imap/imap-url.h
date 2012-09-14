#ifndef IMAP_URL_H
#define IMAP_URL_H

struct imap_url {
	/* server */
	const char *host_name;
	struct ip_addr host_ip;
	in_port_t port;

	/* user */
	const char *userid;
	const char *auth_type;

	/* mailbox */
	const char *mailbox;
	uint32_t uidvalidity;  /* 0 if not set */

	/* message part */
	uint32_t uid;
	const char *section;
	uoff_t partial_offset;
	uoff_t partial_size; /* 0 if not set */

	/* message list (uid == 0) */
	const char *search_program;

	/* urlauth */
	const char *uauth_rumpurl;
	const char *uauth_access_application;
	const char *uauth_access_user;
	const char *uauth_mechanism;
	const unsigned char *uauth_token;
	size_t uauth_token_size;
	time_t uauth_expire; /* (time_t)-1 if not set */

	unsigned int have_host_ip:1; /* url uses IP address */
	unsigned int have_port:1;
	unsigned int have_partial:1;
};

/*
 * IMAP URL parsing
 */

enum imap_url_parse_flags {
	/* Scheme part 'imap:' is already parsed externally. This implies that
	   this is an absolute IMAP URL. */
	IMAP_URL_PARSE_SCHEME_EXTERNAL	= 0x01,
	/* Require relative URL (omitting _both_ scheme and authority), e.g.
	   /MAILBOX/;UID=uid or even ;UID=uid. This flag means that an absolute
	   URL makes no sense in this context. Relative URLs are allowed once a
	   base URL is provided to the parser. */
	IMAP_URL_PARSE_REQUIRE_RELATIVE	= 0x02,
	/* Allow URLAUTH URL */
	IMAP_URL_PARSE_ALLOW_URLAUTH	= 0x04
};

/* Parses full IMAP URL. The returned URL is allocated from data stack. */
int imap_url_parse(const char *url, struct imap_url *base,
		   enum imap_url_parse_flags flags,
		   struct imap_url **url_r, const char **error_r);

/*
 * IMAP URL construction
 */

const char *imap_url_create(const struct imap_url *url);

const char *imap_url_add_urlauth(const char *rumpurl, const char *mechanism,
				 const unsigned char *token, size_t token_len);

#endif
