#ifndef IMAP_URLAUTH_FETCH_H
#define IMAP_URLAUTH_FETCH_H

struct imap_url;
struct imap_urlauth_context;
struct imap_urlauth_fetch;

enum imap_urlauth_fetch_flags {
	/* Indicates that this is an extended request */
	IMAP_URLAUTH_FETCH_FLAG_EXTENDED		= 0x01,
	/* Fetch body part unmodified */
	IMAP_URLAUTH_FETCH_FLAG_BODY			= 0x02,
	/* Fetch body part as binary, i.e. without content encoding */
	IMAP_URLAUTH_FETCH_FLAG_BINARY			= 0x04,
	/* Fetch IMAP bodypartstructure */
	IMAP_URLAUTH_FETCH_FLAG_BODYPARTSTRUCTURE	= 0x08,
};

struct imap_urlauth_fetch_reply {
	const char *url;
	enum imap_urlauth_fetch_flags flags;

	struct istream *input;
	uoff_t size;

	const char *bodypartstruct;
	const char *error;

	unsigned int succeeded:1;
	unsigned int binary_has_nuls:1;
};

/* Callback to handle fetch reply. Returns 1 if handled completely and ready
   for next reply, 0 if not all data was processed, and -1 for error. If a
   callback returns 0, imap_urlauth_fetch_continue() must be called once
   new replies may be processed. If this is the last request to yield a reply,
   argument last is TRUE. */
typedef int
imap_urlauth_fetch_callback_t(struct imap_urlauth_fetch_reply *reply,
			      bool last, void *context);

struct imap_urlauth_fetch *
imap_urlauth_fetch_init(struct imap_urlauth_context *uctx,
			imap_urlauth_fetch_callback_t *callback, void *context);
void imap_urlauth_fetch_deinit(struct imap_urlauth_fetch **ufetch);

int imap_urlauth_fetch_url(struct imap_urlauth_fetch *ufetch, const char *url,
			   enum imap_urlauth_fetch_flags url_flags);
int imap_urlauth_fetch_url_parsed(struct imap_urlauth_fetch *ufetch,
			   const char *url, struct imap_url *imap_url,
			   enum imap_urlauth_fetch_flags url_flags);

bool imap_urlauth_fetch_continue(struct imap_urlauth_fetch *ufetch);
bool imap_urlauth_fetch_is_pending(struct imap_urlauth_fetch *ufetch);

#endif
