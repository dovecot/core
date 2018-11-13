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
quota_is_over(uoff_t alloc, int64_t used, uint64_t ceil, uint64_t over,
	      uoff_t *overrun_r)
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
				if (overrun_r != NULL)
					*overrun_r = (over - deleted) + alloc;
				return TRUE;
			}
			if (alloc > (deleted - over)) {
				/* We are under quota after deletions, but the
				   the new allocation exceeds the quota once
				   more. */
				if (overrun_r != NULL)
					*overrun_r = alloc - (deleted - over);
				return TRUE;
			}
		} else {
			/* We were under quota even before deleting the
			   messages. */
			if (alloc > deleted && (alloc - deleted) > ceil) {
				/* The new allocation exceeds the quota limit.
				 */
				if (overrun_r != NULL)
					*overrun_r = (alloc - deleted) - ceil;
				return TRUE;
			}
		}
	} else {
		/* Resource usage increased in this transaction. */
		if (over > 0) {
			/* Resource usage is already over quota. */
			if (overrun_r != NULL)
				*overrun_r = over + (uoff_t)used + alloc;
			return TRUE;
		}
		if (ceil < alloc || (ceil - alloc) < (uint64_t)used) {
			/* Limit reached. */
			if (overrun_r != NULL)
				*overrun_r = (uoff_t)used + alloc - ceil;
			return TRUE;
		}
	}

	/* Not over quota. */
	if (overrun_r != NULL)
		*overrun_r = 0;
	return FALSE;
}

void quota_used_apply_expunged(int64_t *used, uint64_t expunged)
{
	int64_t exp_signed;
	int64_t exp_overflow;

	if (expunged < (uint64_t)INT64_MAX) {
		exp_overflow = 0;
		exp_signed = (int64_t)expunged;
	} else {
		exp_overflow = (int64_t)(expunged - INT64_MAX);
		exp_signed = INT64_MAX;
	}

	if (INT64_MIN + exp_signed > *used)
		*used = INT64_MIN;
	else
		*used -= exp_signed;
	if (INT64_MIN + (int64_t)exp_overflow > *used)
		*used = INT64_MIN;
	else
		*used -= exp_overflow;
}

bool quota_transaction_is_over(struct quota_transaction_context *ctx,
			       uoff_t size)
{
	int64_t count_used = ctx->count_used;
	int64_t bytes_used = ctx->bytes_used;

	quota_used_apply_expunged(&count_used, ctx->count_expunged);
	quota_used_apply_expunged(&bytes_used, ctx->bytes_expunged);

	if (quota_is_over(1, count_used, ctx->count_ceil,
			  ctx->count_over, NULL))
		return TRUE;
	if (quota_is_over(size, bytes_used, ctx->bytes_ceil,
			  ctx->bytes_over, NULL))
		return TRUE;
	return FALSE;
}

bool quota_root_is_over(struct quota_transaction_context *ctx,
			struct quota_transaction_root_context *root,
			uoff_t count_alloc, uoff_t bytes_alloc,
			uoff_t count_expunged, uoff_t bytes_expunged,
			uoff_t *count_overrun_r, uoff_t *bytes_overrun_r)
{
	int64_t count_used = ctx->count_used;
	int64_t bytes_used = ctx->bytes_used;

	*count_overrun_r = 0;
	*bytes_overrun_r = 0;

	quota_used_apply_expunged(&count_used, root->count_expunged);
	quota_used_apply_expunged(&bytes_used, root->bytes_expunged);
	quota_used_apply_expunged(&count_used, count_expunged);
	quota_used_apply_expunged(&bytes_used, bytes_expunged);

	return (quota_is_over(count_alloc, count_used,
			      root->count_ceil, root->count_over,
			      count_overrun_r) ||
		quota_is_over(bytes_alloc, bytes_used,
			      root->bytes_ceil, root->bytes_over,
			      bytes_overrun_r));
}

void quota_transaction_root_expunged(
	struct quota_transaction_root_context *rctx,
	uint64_t count_expunged, uint64_t bytes_expunged)
{
	if ((UINT64_MAX - count_expunged) < rctx->count_expunged)
		rctx->count_expunged = UINT64_MAX;
	else
		rctx->count_expunged += count_expunged;
	if ((UINT64_MAX - bytes_expunged) < rctx->bytes_expunged)
		rctx->bytes_expunged = UINT64_MAX;
	else
		rctx->bytes_expunged += bytes_expunged;
}

void quota_transaction_update_expunged(struct quota_transaction_context *ctx)
{
	uint64_t count_ceil, bytes_ceil;
	unsigned int i;

	/* Calculate effective ceilings for the whole transaction based on
	   per-root expunge values. */
	count_ceil = bytes_ceil = 0;
	for (i = 0; i < array_count(&ctx->quota->all_roots); i++) {
		struct quota_transaction_root_context *rctx = &ctx->roots[i];
		uint64_t ceil;

		/* count */
		ceil = rctx->count_ceil;
		if ((UINT64_MAX - rctx->count_expunged) < ceil)
			ceil = UINT64_MAX;
		else
			ceil += rctx->count_expunged;
		if (rctx->count_over < ceil)
			ceil -= rctx->count_over;
		else
			ceil = 0;
		if (count_ceil == 0 || count_ceil > ceil)
			count_ceil = ceil;
		/* bytes */
		ceil = rctx->bytes_ceil;
		if ((UINT64_MAX - rctx->bytes_expunged) < ceil)
			ceil = UINT64_MAX;
		else
			ceil += rctx->bytes_expunged;
		if (rctx->bytes_over < ceil)
			ceil -= rctx->bytes_over;
		else
			ceil = 0;
		if (bytes_ceil == 0 || bytes_ceil > ceil)
			bytes_ceil = ceil;
	}
	/* Use the difference between the real and effective ceilings to
	   determine the updated effective expunge values */
	i_assert(count_ceil >= ctx->count_ceil);
	ctx->count_expunged = count_ceil - ctx->count_ceil;
	i_assert(bytes_ceil >= ctx->bytes_ceil);
	ctx->bytes_expunged = bytes_ceil - ctx->bytes_ceil;
}
