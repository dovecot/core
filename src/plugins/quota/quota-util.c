/* Copyright (c) 2005-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "quota-private.h"

bool quota_warning_match(const struct quota_root_settings *w,
			 uint64_t bytes_before, uint64_t bytes_current,
			 uint64_t count_before, uint64_t count_current,
			 const char **reason_r)
{
#define QUOTA_EXCEEDED(before, current, limit) \
	((before) < (uint64_t)(limit) && (current) >= (uint64_t)(limit))
	uint64_t bytes_limit = (uint64_t)w->quota_storage_size *
		(uint64_t)w->quota_storage_percentage / 100ULL;
	uint64_t count_limit = (uint64_t)w->quota_message_count *
		(uint64_t)w->quota_message_percentage / 100ULL;
	if (strcmp(w->quota_warning_threshold, QUOTA_WARNING_THRESHOLD_OVER) == 0) {
		/* over quota (default) */
		if (strcmp(w->quota_warning_resource, QUOTA_WARNING_RESOURCE_STORAGE) == 0 &&
		    QUOTA_EXCEEDED(bytes_before, bytes_current, bytes_limit)) {
			*reason_r = t_strdup_printf("bytes=%"PRIu64" -> %"PRIu64" over limit %"PRId64,
				bytes_before, bytes_current, bytes_limit);
			return TRUE;
		}
		if (strcmp(w->quota_warning_resource, QUOTA_WARNING_RESOURCE_MESSAGE) == 0 &&
		    QUOTA_EXCEEDED(count_before, count_current, count_limit)) {
			*reason_r = t_strdup_printf("count=%"PRIu64" -> %"PRIu64" over limit %"PRId64,
				count_before, count_current, count_limit);
			return TRUE;
		}
	} else {
		if (strcmp(w->quota_warning_resource, QUOTA_WARNING_RESOURCE_STORAGE) == 0 &&
		    QUOTA_EXCEEDED(bytes_current, bytes_before, bytes_limit)) {
			*reason_r = t_strdup_printf("bytes=%"PRIu64" -> %"PRIu64" below limit %"PRId64,
				bytes_before, bytes_current, bytes_limit);
			return TRUE;
		}
		if (strcmp(w->quota_warning_resource, QUOTA_WARNING_RESOURCE_MESSAGE) == 0 &&
		    QUOTA_EXCEEDED(count_current, count_before, count_limit)) {
			*reason_r = t_strdup_printf("count=%"PRIu64" -> %"PRIu64" below limit %"PRId64,
				count_before, count_current, count_limit);
			return TRUE;
		}
	}
	return FALSE;
}

int quota_get_mail_size(struct quota_transaction_context *ctx,
			struct mail *mail, uoff_t *size_r)
{
	if (ctx->quota->vsizes)
		return mail_get_virtual_size(mail, size_r);
	else
		return mail_get_physical_size(mail, size_r);
}

static inline bool
quota_is_over(uoff_t alloc, int64_t used, uint64_t ceil, uint64_t over)
{
	/* The over parameter is the amount by which the resource usage exceeds
	   the limit already. The ceil parameter is the amount by which the
	   resource usage is allowed to increase before crossing the limit.
	   Therefore, the over and ceil values are mutually exclusive; these
	   cannot both be nonzero. */
	i_assert(over == 0 || ceil == 0);

	if (used < 0) {
		/* Resource usage decreased in this transaction. */
		const uint64_t deleted = (uint64_t)-used;

		if (over > 0) {
			/* We were over quota before deleting the messages. */
			if (over > deleted) {
				/* We are over quota, even after deletions and
				   without the new allocation. */
				return TRUE;
			}
			if (alloc > (deleted - over)) {
				/* We are under quota after deletions, but the
				   the new allocation exceeds the quota once
				   more. */
				return TRUE;
			}
		} else {
			/* We were under quota even before deleting the
			   messages. */
			if (alloc > deleted && (alloc - deleted) > ceil) {
				/* The new allocation exceeds the quota limit.
				 */
				return TRUE;
			}
		}
	} else {
		/* Resource usage increased in this transaction. */
		if (over > 0) {
			/* Resource usage is already over quota. */
			return TRUE;
		}
		if (ceil < alloc || (ceil - alloc) < (uint64_t)used) {
			/* Limit reached. */
			return TRUE;
		}
	}

	/* Not over quota. */
	return FALSE;
}

bool quota_transaction_is_over(struct quota_transaction_context *ctx,
			       uoff_t size)
{
	if (quota_is_over(1, ctx->count_used, ctx->count_ceil,
			  ctx->count_over))
		return TRUE;
	if (quota_is_over(size, ctx->bytes_used, ctx->bytes_ceil,
			  ctx->bytes_over))
		return TRUE;
	return FALSE;
}
