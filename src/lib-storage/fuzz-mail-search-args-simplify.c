/* Copyright (c) Dovecot authors, see top-level COPYING file */

/* Differential fuzzing of mail_search_args_simplify(): The input is parsed
   as an IMAP SEARCH query and evaluated against a fixed set of synthetic
   mails, both before and after it is simplified. The results must be the
   same, simplifying the args again must not change them, and all the args
   must stay initialized. Anything that can't be modeled (text searches,
   GUIDs, ..) is an opaque predicate: the same arg matches the same mails
   every time. */

#include "lib.h"
#include "str.h"
#include "crc32.h"
#include "seq-range-array.h"
#include "fuzzer.h"
#include "mail-storage-private.h"
#include "mail-search-build.h"
#include "mail-search-parser.h"
#include "mail-search.h"

#define FUZZ_MAILS_COUNT 24
#define FUZZ_THREADS_COUNT 4
#define FUZZ_MAX_INTHREAD_DEPTH 3
/* 01-Aug-2014 00:00:00 UTC */
#define FUZZ_BASE_TIME 1406851200

struct fuzz_mail {
	uint32_t seq;
	uoff_t size;
	uint64_t modseq;
	time_t sent_date, recv_date, saved_date;
	enum mail_flags flags;
	unsigned int thread;
};

static struct fuzz_mail fuzz_mails[FUZZ_MAILS_COUNT];
static bool fuzz_mails_initialized = FALSE;

static uint32_t fuzz_mix(uint32_t x)
{
	x ^= x >> 16;
	x *= 0x7feb352dU;
	x ^= x >> 15;
	x *= 0x846ca68bU;
	x ^= x >> 16;
	return x;
}

static void fuzz_mails_init(void)
{
	unsigned int i;

	for (i = 0; i < FUZZ_MAILS_COUNT; i++) {
		struct fuzz_mail *mail = &fuzz_mails[i];
		uint32_t r = fuzz_mix(i + 1);

		mail->seq = i + 1;
		/* include exact multiples of 100 */
		mail->size = (r & 3) == 0 ? (r >> 2) % 4 * 100 : (r >> 2) % 400;
		mail->modseq = 1 + (r >> 8) % 8;
		/* -2 .. +3 days around the base time, half of them at
		   midnight */
		mail->sent_date = FUZZ_BASE_TIME +
			((int)((r >> 12) % 6) - 2) * 3600*24 +
			((r & 0x10000) != 0 ? 0 : (int)((r >> 17) % (3600*24)));
		r = fuzz_mix(r);
		mail->recv_date = FUZZ_BASE_TIME +
			((int)((r >> 12) % 6) - 2) * 3600*24 +
			((r & 0x10000) != 0 ? 0 : (int)((r >> 17) % (3600*24)));
		r = fuzz_mix(r);
		mail->saved_date = FUZZ_BASE_TIME +
			((int)((r >> 12) % 6) - 2) * 3600*24 +
			((r & 0x10000) != 0 ? 0 : (int)((r >> 17) % (3600*24)));
		r = fuzz_mix(r);
		mail->flags = r & (MAIL_ANSWERED | MAIL_FLAGGED | MAIL_DELETED |
				   MAIL_SEEN | MAIL_DRAFT | MAIL_RECENT);
		mail->thread = i % FUZZ_THREADS_COUNT;
	}
}

static struct mail_search_args *
fuzz_build_search_args(const char *str, const char **error_r)
{
	struct mail_search_parser *parser;
	struct mail_search_args *args;
	const char *charset = "UTF-8";
	int ret;

	parser = mail_search_parser_init_cmdline(t_strsplit(str, " "));
	ret = mail_search_build(mail_search_register_get_imap4rev1(),
				parser, &charset, &args, error_r);
	mail_search_parser_deinit(&parser);
	return ret < 0 ? NULL : args;
}

/* Returns FALSE if the args contain something that can't be evaluated. */
static bool fuzz_args_supported(const struct mail_search_arg *args,
				unsigned int inthread_depth)
{
	const struct mail_search_arg *arg;

	for (arg = args; arg != NULL; arg = arg->next) {
		switch (arg->type) {
		case SEARCH_MAILBOX_GLOB:
			/* initializing needs a mailbox list */
			return FALSE;
		case SEARCH_MIMEPART:
			return FALSE;
		case SEARCH_INTHREAD:
			/* evaluation cost grows exponentially with the
			   nesting depth */
			if (inthread_depth >= FUZZ_MAX_INTHREAD_DEPTH)
				return FALSE;
			if (!fuzz_args_supported(arg->value.subargs,
						 inthread_depth + 1))
				return FALSE;
			break;
		case SEARCH_SUB:
		case SEARCH_OR:
			if (!fuzz_args_supported(arg->value.subargs,
						 inthread_depth))
				return FALSE;
			break;
		default:
			break;
		}
	}
	return TRUE;
}

static bool fuzz_args_initialized(const struct mail_search_arg *args)
{
	const struct mail_search_arg *arg;

	for (arg = args; arg != NULL; arg = arg->next) {
		switch (arg->type) {
		case SEARCH_MODSEQ:
			if (arg->value.str != NULL &&
			    arg->initialized.keywords == NULL)
				return FALSE;
			break;
		case SEARCH_KEYWORDS:
			if (arg->initialized.keywords == NULL)
				return FALSE;
			break;
		case SEARCH_INTHREAD:
			if (arg->initialized.search_args == NULL)
				return FALSE;
			/* fall through */
		case SEARCH_SUB:
		case SEARCH_OR:
			if (!fuzz_args_initialized(arg->value.subargs))
				return FALSE;
			break;
		default:
			break;
		}
	}
	return TRUE;
}

/* Opaque predicate: A hash of everything that mail_search_arg_one_equals()
   compares, so that equal args are the same predicate and different args
   are (almost certainly) different predicates. */
static bool fuzz_opaque_match(const struct mail_search_arg *arg,
			      const struct fuzz_mail *mail)
{
	unsigned char fuzzy = arg->fuzzy ? 1 : 0;
	uint32_t hash;

	hash = crc32_data(&arg->type, sizeof(arg->type));
	hash = crc32_data_more(hash, &arg->value.search_flags,
			       sizeof(arg->value.search_flags));
	hash = crc32_data_more(hash, &fuzzy, sizeof(fuzzy));
	if (arg->hdr_field_name != NULL)
		hash = crc32_str_more(hash, t_str_lcase(arg->hdr_field_name));
	if (arg->value.str != NULL)
		hash = crc32_str_more(hash, arg->value.str);
	return (fuzz_mix(hash + mail->seq) & 1) != 0;
}

static time_t fuzz_mail_date(const struct fuzz_mail *mail,
			     enum mail_search_date_type type)
{
	switch (type) {
	case MAIL_SEARCH_DATE_TYPE_SENT:
		return mail->sent_date;
	case MAIL_SEARCH_DATE_TYPE_RECEIVED:
		return mail->recv_date;
	case MAIL_SEARCH_DATE_TYPE_SAVED:
		return mail->saved_date;
	}
	i_unreached();
}

static bool fuzz_eval_args(const struct mail_search_arg *args,
			   const struct fuzz_mail *mail, bool and_args);

static bool fuzz_eval_inthread(const struct mail_search_arg *arg,
			       const struct fuzz_mail *mail)
{
	unsigned int i;

	/* matches if any mail in the same thread matches */
	for (i = 0; i < FUZZ_MAILS_COUNT; i++) {
		if (fuzz_mails[i].thread == mail->thread &&
		    fuzz_eval_args(arg->value.subargs, &fuzz_mails[i], TRUE))
			return TRUE;
	}
	return FALSE;
}

static bool fuzz_eval_arg(const struct mail_search_arg *arg,
			  const struct fuzz_mail *mail)
{
	time_t date;
	bool ret;

	switch (arg->type) {
	case SEARCH_ALL:
	case SEARCH_SAVEDATESUPPORTED:
		ret = TRUE;
		break;
	case SEARCH_SUB:
		ret = fuzz_eval_args(arg->value.subargs, mail, TRUE);
		break;
	case SEARCH_OR:
		ret = fuzz_eval_args(arg->value.subargs, mail, FALSE);
		break;
	case SEARCH_INTHREAD:
		ret = fuzz_eval_inthread(arg, mail);
		break;
	case SEARCH_SEQSET:
	case SEARCH_UIDSET:
	case SEARCH_REAL_UID:
		/* uid == seq */
		ret = seq_range_exists(&arg->value.seqset, mail->seq);
		break;
	case SEARCH_FLAGS:
		ret = (mail->flags & arg->value.flags) == arg->value.flags;
		break;
	case SEARCH_MODSEQ:
		ret = mail->modseq >= arg->value.modseq->modseq;
		break;
	case SEARCH_SMALLER:
		ret = mail->size < arg->value.size;
		break;
	case SEARCH_LARGER:
		ret = mail->size > arg->value.size;
		break;
	case SEARCH_BEFORE:
		date = fuzz_mail_date(mail, arg->value.date_type);
		ret = date < arg->value.time;
		break;
	case SEARCH_SINCE:
		date = fuzz_mail_date(mail, arg->value.date_type);
		ret = date >= arg->value.time;
		break;
	case SEARCH_ON:
		date = fuzz_mail_date(mail, arg->value.date_type);
		ret = date >= arg->value.time &&
			date < arg->value.time + 3600*24;
		break;
	case SEARCH_BODY:
	case SEARCH_TEXT:
		/* BODY "" and TEXT "" match everything */
		ret = arg->value.str[0] == '\0' ||
			fuzz_opaque_match(arg, mail);
		break;
	default:
		ret = fuzz_opaque_match(arg, mail);
		break;
	}
	return arg->match_not ? !ret : ret;
}

static bool fuzz_eval_args(const struct mail_search_arg *args,
			   const struct fuzz_mail *mail, bool and_args)
{
	const struct mail_search_arg *arg;

	for (arg = args; arg != NULL; arg = arg->next) {
		bool ret = fuzz_eval_arg(arg, mail);

		if (and_args && !ret)
			return FALSE;
		if (!and_args && ret)
			return TRUE;
	}
	return and_args;
}

static uint32_t fuzz_eval_all(const struct mail_search_args *args)
{
	uint32_t matches = 0;
	unsigned int i;

	for (i = 0; i < FUZZ_MAILS_COUNT; i++) {
		if (fuzz_eval_args(args->args, &fuzz_mails[i], TRUE))
			matches |= 1U << i;
	}
	return matches;
}

static const char *fuzz_args_to_imap(const struct mail_search_args *args)
{
	string_t *str = t_str_new(256);
	const char *error;

	if (!mail_search_args_to_imap(str, args->args, FALSE, &error))
		return t_strdup_printf("<%s>", error);
	return str_c(str);
}

static void fuzz_search_args(const char *input)
{
	struct mail_storage_settings set = { .mail_max_keyword_length = 100 };
	struct mail_storage storage = { .set = &set };
	struct mailbox box = { .opened = TRUE, .storage = &storage };
	struct mail_search_args *ref_args, *args;
	const char *error, *simplified, *simplified2;
	uint32_t ref_matches, matches;

	if (!fuzz_mails_initialized) {
		fuzz_mails_initialized = TRUE;
		fuzz_mails_init();
	}
	/* lib_init() and lib_deinit() are called for each input, so nothing
	   that registers with lib can be kept across inputs */
	mail_storage_init();

	ref_args = fuzz_build_search_args(input, &error);
	if (ref_args == NULL) {
		mail_storage_deinit();
		return;
	}
	if (!fuzz_args_supported(ref_args->args, 0)) {
		mail_search_args_unref(&ref_args);
		mail_storage_deinit();
		return;
	}
	args = fuzz_build_search_args(input, &error);
	i_assert(args != NULL);

	box.index = mail_index_alloc(NULL, NULL, "dovecot.index.");

	/* reference: initialize without simplifying */
	ref_args->simplified = TRUE;
	mail_search_args_init(ref_args, &box, FALSE, NULL);
	ref_matches = fuzz_eval_all(ref_args);

	/* the normal flow: mail_search_args_init() simplifies the args before
	   initializing them */
	mail_search_args_init(args, &box, FALSE, NULL);
	simplified = fuzz_args_to_imap(args);
	matches = fuzz_eval_all(args);
	if (matches != ref_matches) {
		i_panic("Simplified args match different mails: '%s' -> '%s' (0x%x vs 0x%x)",
			input, simplified, ref_matches, matches);
	}
	if (!fuzz_args_initialized(args->args)) {
		i_panic("Simplified args not initialized: '%s' -> '%s'",
			input, simplified);
	}

	/* simplifying already simplified and initialized args must not
	   change anything */
	mail_search_args_simplify(args);
	simplified2 = fuzz_args_to_imap(args);
	if (strcmp(simplified, simplified2) != 0) {
		i_panic("Simplifying isn't idempotent: '%s' -> '%s' -> '%s'",
			input, simplified, simplified2);
	}
	if (!fuzz_args_initialized(args->args)) {
		i_panic("Re-simplified args not initialized: '%s' -> '%s'",
			input, simplified);
	}

	mail_search_args_deinit(args);
	mail_search_args_unref(&args);
	mail_search_args_deinit(ref_args);
	mail_search_args_unref(&ref_args);
	mail_index_free(&box.index);
	mail_storage_deinit();
}

FUZZ_BEGIN_STR(const char *input)
{
	fuzz_search_args(input);
}
FUZZ_END
