#ifndef FTS_API_PRIVATE_H
#define FTS_API_PRIVATE_H

#include "unichar.h"
#include "fts-api.h"

struct mail_user;
struct mailbox_list;

#define MAILBOX_GUID_HEX_LENGTH (GUID_128_SIZE*2)

struct fts_backend_vfuncs {
	struct fts_backend *(*alloc)(void);
	int (*init)(struct fts_backend *backend, const char **error_r);
	void (*deinit)(struct fts_backend *backend);

	int (*get_last_uid)(struct fts_backend *backend, struct mailbox *box,
			    uint32_t *last_uid_r);

	struct fts_backend_update_context *
		(*update_init)(struct fts_backend *backend);
	int (*update_deinit)(struct fts_backend_update_context *ctx);

	void (*update_set_mailbox)(struct fts_backend_update_context *ctx,
				   struct mailbox *box);
	void (*update_expunge)(struct fts_backend_update_context *ctx,
			       uint32_t uid);

	/* Start a build for specified key */
	bool (*update_set_build_key)(struct fts_backend_update_context *ctx,
				    const struct fts_backend_build_key *key);
	/* Finish a build for specified key - guaranteed to be called */
	void (*update_unset_build_key)(struct fts_backend_update_context *ctx);
	/* Add data for current build key */
	int (*update_build_more)(struct fts_backend_update_context *ctx,
				 const unsigned char *data, size_t size);

	int (*refresh)(struct fts_backend *backend);
	int (*rescan)(struct fts_backend *backend);
	int (*optimize)(struct fts_backend *backend);

	bool (*can_lookup)(struct fts_backend *backend,
			   const struct mail_search_arg *args);
	int (*lookup)(struct fts_backend *backend, struct mailbox *box,
		      struct mail_search_arg *args, bool and_args,
		      struct fts_result *result);
	int (*lookup_multi)(struct fts_backend *backend,
			    struct mailbox *const boxes[],
			    struct mail_search_arg *args, bool and_args,
			    struct fts_multi_result *result);
	void (*lookup_done)(struct fts_backend *backend);
};

enum fts_backend_flags {
	/* Backend supports indexing binary MIME parts */
	FTS_BACKEND_FLAG_BINARY_MIME_PARTS	= 0x01,
	/* Send built text to backend normalized rather than
	   preserving original case */
	FTS_BACKEND_FLAG_NORMALIZE_INPUT	= 0x02,
	/* Send only fully indexable words rather than randomly sized blocks */
	FTS_BACKEND_FLAG_BUILD_FULL_WORDS	= 0x04,
	/* Fuzzy search works */
	FTS_BACKEND_FLAG_FUZZY_SEARCH		= 0x08
};

struct fts_backend {
	const char *name;
	enum fts_backend_flags flags;

	struct fts_backend_vfuncs v;
	struct mail_namespace *ns;

	unsigned int updating:1;
};

struct fts_backend_update_context {
	struct fts_backend *backend;
	normalizer_func_t *normalizer;

	struct mailbox *cur_box, *backend_box;

	unsigned int build_key_open:1;
	unsigned int failed:1;
};

struct fts_index_header {
	uint32_t last_indexed_uid;

	/* Checksum of settings. If the settings change, the index should
	   be rebuilt. */
	uint32_t settings_checksum;
	uint32_t unused;
};

void fts_backend_register(const struct fts_backend *backend);
void fts_backend_unregister(const char *name);

bool fts_backend_default_can_lookup(struct fts_backend *backend,
				    const struct mail_search_arg *args);

void fts_filter_uids(ARRAY_TYPE(seq_range) *definite_dest,
		     const ARRAY_TYPE(seq_range) *definite_filter,
		     ARRAY_TYPE(seq_range) *maybe_dest,
		     const ARRAY_TYPE(seq_range) *maybe_filter);

/* Returns TRUE if ok, FALSE if no fts header */
bool fts_index_get_header(struct mailbox *box, struct fts_index_header *hdr_r);
int fts_index_set_header(struct mailbox *box,
			 const struct fts_index_header *hdr);
int ATTR_NOWARN_UNUSED_RESULT
fts_index_set_last_uid(struct mailbox *box, uint32_t last_uid);
int fts_index_have_compatible_settings(struct mailbox_list *list,
				       uint32_t checksum);

/* Returns TRUE if FTS backend should index the header for optimizing
   separate lookups */
bool fts_header_want_indexed(const char *hdr_name);

int fts_mailbox_get_guid(struct mailbox *box, const char **guid_r);

#endif
