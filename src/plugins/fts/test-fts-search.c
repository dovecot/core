#include "lib.h"
#include "str.h"
#include "array.h"
#include "test-common.h"
#include "fts-api.h"
#include "fts-storage.h"

/* Mocks */
struct mailbox;

static struct fts_backend *test_fts_mailbox_backend(struct mailbox *box ATTR_UNUSED) {
        return NULL;
}
static int test_fts_backend_lookup(struct fts_backend *backend ATTR_UNUSED,
                                   struct mailbox *box ATTR_UNUSED,
                                   struct mail_search_arg *args ATTR_UNUSED,
                                   enum fts_lookup_flags flags ATTR_UNUSED,
                                   struct fts_result *result ATTR_UNUSED) {
        return 0;
}
static void test_fts_search_serialize(buffer_t *buf ATTR_UNUSED,
                                      const struct mail_search_arg *args ATTR_UNUSED) {
        return;
}
static int test_fts_backend_lookup_multi(struct fts_backend *backend ATTR_UNUSED,
                                         struct mailbox *const boxes[] ATTR_UNUSED,
                                         struct mail_search_arg *args ATTR_UNUSED,
                                         enum fts_lookup_flags flags ATTR_UNUSED,
                                         struct fts_multi_result *result ATTR_UNUSED) {
        return 0;
}
static int test_fts_mailbox_get_status(struct mailbox *box ATTR_UNUSED,
                                       enum mailbox_status_items items ATTR_UNUSED,
                                       struct mailbox_status *status_r) {
        /* avoid uninitialized warning */
        status_r->uidnext = 0;
        return 0;
}
static int test_fts_backend_refresh(struct fts_backend *backend ATTR_UNUSED,
                                    struct mailbox *box ATTR_UNUSED) {
        return 0;
}
static int test_fts_backend_is_uid_indexed(struct fts_backend *backend ATTR_UNUSED,
                                           struct mailbox *box ATTR_UNUSED,
                                           uint32_t uid ATTR_UNUSED,
                                           uint32_t *last_indexed_uid_r) {
        /* avoid uninitialized warning */
        *last_indexed_uid_r = 0;
        return 0;
}
static void test_fts_search_deserialize(struct mail_search_arg *args ATTR_UNUSED,
                                        const buffer_t *buf ATTR_UNUSED) {
        return;
}
static void test_fts_backend_lookup_done(struct fts_backend *backend ATTR_UNUSED) {
        return;
}
static int test_fts_search_args_expand(struct fts_backend *backend ATTR_UNUSED,
                                       struct mail_search_args *args ATTR_UNUSED) {
        return 0;
}

/* Redirects */
#define fts_mailbox_backend test_fts_mailbox_backend
#define fts_backend_lookup test_fts_backend_lookup
#define fts_search_serialize test_fts_search_serialize
#define fts_backend_lookup_multi test_fts_backend_lookup_multi
#define fts_mailbox_get_status test_fts_mailbox_get_status
#define fts_backend_refresh test_fts_backend_refresh
#define fts_backend_is_uid_indexed test_fts_backend_is_uid_indexed
#define fts_search_deserialize test_fts_search_deserialize
#define fts_backend_lookup_done test_fts_backend_lookup_done
#define fts_search_args_expand test_fts_search_args_expand

#include "fts-search.c"

const struct fts_score_map mso_dest_before[] = {
        { .uid = 1, .score = 0.1 },
        { .uid = 2, .score = 0.2 },
};
const struct fts_score_map mso_src[] = {
        { .uid = 0, .score = 1.0 },
        { .uid = 1, .score = 0.9 },
};
/* mso_dest_before "OR" mso_src should result in: */
const struct fts_score_map mso_dest_after[] = {
        { .uid = 0, .score = 1.0 },
        { .uid = 1, .score = 0.9 },
        { .uid = 2, .score = 0.2 },
};

static const unsigned int mso_dest_before_count = N_ELEMENTS(mso_dest_before);
static const unsigned int mso_src_count = N_ELEMENTS(mso_src);
static const unsigned int mso_dest_after_count = N_ELEMENTS(mso_dest_after);

static void test_merge_scores_or(void)
{
        ARRAY_TYPE(fts_score_map) dest;
        ARRAY_TYPE(fts_score_map) src_array;
        const struct fts_score_map *dest_map;
        unsigned int dest_count;

	test_begin("merge_scores_or");

        t_array_init(&dest, 0);
        for (unsigned int i=0; i<mso_dest_before_count; i++) {
                array_push_back(&dest, &mso_dest_before[i]);
        }
        t_array_init(&src_array, 0);
        for (unsigned int i=0; i<mso_src_count; i++) {
                array_push_back(&src_array, &mso_src[i]);
        }
        
        fts_search_merge_scores_or(&dest, &src_array);

        dest_map = array_get(&dest, &dest_count);
	test_assert(dest_count == mso_dest_after_count);
	if (dest_count != mso_dest_after_count) {
                i_error("fts_score_map array dest does not contain "
                        "the expected %d elements but %d",
                        mso_dest_after_count, dest_count);
        } else {
                for (unsigned int i=0; i<dest_count; i++) {
                        test_assert(dest_map[i].score == mso_dest_after[i].score);
                        if (dest_map[i].score != mso_dest_after[i].score) {
                                i_warning("fts_score_map dest[%d] is not { .uid=%d, "
                                          ".score=%.01f } but { .uid=%d, .score=%.01f }",
                                          i, mso_dest_after[i].uid, mso_dest_after[i].score,
                                          dest_map[i].uid, dest_map[i].score);
                        }
                }
        }

	test_end();
}

int main(void)
{
	static void (*const test_functions[])(void) = {
		test_merge_scores_or,
		NULL
	};
	return test_run(test_functions);
}
