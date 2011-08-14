/* Copyright (c) 2006-2010 Dovecot authors, see the included COPYING file */

extern "C" {
#include "lib.h"
#include "array.h"
#include "unichar.h"
#include "hash.h"
#include "hex-binary.h"
#include "mail-index.h"
#include "mail-search.h"
#include "mail-namespace.h"
#include "mail-storage.h"
#include "fts-expunge-log.h"
#include "lucene-wrapper.h"

#include <sys/stat.h>
#ifdef HAVE_LUCENE_TEXTCAT
#  include <libtextcat/textcat.h>
#endif
};
#include <CLucene.h>
#include <CLucene/util/CLStreams.h>
#include <CLucene/search/MultiPhraseQuery.h>
#include "SnowballAnalyzer.h"

/* Lucene's default is 10000. Use it here also.. */
#define MAX_TERMS_PER_DOCUMENT 10000

#define LUCENE_LOCK_OVERRIDE_SECS 60

#define DEFAULT_LANGUAGE "english"

using namespace lucene::document;
using namespace lucene::index;
using namespace lucene::search;
using namespace lucene::queryParser;
using namespace lucene::analysis;
using namespace lucene::analysis;
using namespace lucene::util;

struct lucene_analyzer {
	char *lang;
	Analyzer *analyzer;
};

struct lucene_index {
	char *path;
	char *textcat_dir, *textcat_conf;
	wchar_t mailbox_guid[MAILBOX_GUID_HEX_LENGTH + 1];

	IndexReader *reader;
	IndexWriter *writer;
	IndexSearcher *searcher;

	Analyzer *default_analyzer, *cur_analyzer;
	ARRAY_DEFINE(analyzers, struct lucene_analyzer);

	Document *doc;
	uint32_t prev_uid;
};

struct rescan_context {
	struct lucene_index *index;
	struct mailbox_list *list;

	struct mailbox *box;
	mail_guid_128_t box_guid;
	int box_ret;

	ARRAY_TYPE(seq_range) uids;
	struct seq_range_iter uids_iter;
	unsigned int uids_iter_n;

	uint32_t last_existing_uid;
	bool warned;
};

static void *textcat = NULL;
static bool textcat_broken = FALSE;
static int textcat_refcount = 0;

struct lucene_index *lucene_index_init(const char *path,
				       const char *textcat_dir,
				       const char *textcat_conf)
{
	struct lucene_index *index;

	index = i_new(struct lucene_index, 1);
	index->path = i_strdup(path);
	index->textcat_dir = i_strdup(textcat_dir);
	index->textcat_conf = i_strdup(textcat_conf);
#ifdef HAVE_LUCENE_TEXTCAT
	index->default_analyzer = _CLNEW snowball::SnowballAnalyzer(DEFAULT_LANGUAGE);
#else
	index->default_analyzer = _CLNEW standard::StandardAnalyzer();
#endif
	i_array_init(&index->analyzers, 32);
	textcat_refcount++;

	return index;
}

void lucene_index_close(struct lucene_index *index)
{
	_CLDELETE(index->reader);
	_CLDELETE(index->writer);
	_CLDELETE(index->searcher);
}

void lucene_index_deinit(struct lucene_index *index)
{
	struct lucene_analyzer *a;

	lucene_index_close(index);
	array_foreach_modifiable(&index->analyzers, a) {
		i_free(a->lang);
		_CLDELETE(a->analyzer);
	}
	array_free(&index->analyzers);
	if (--textcat_refcount == 0 && textcat != NULL) {
#ifdef HAVE_LUCENE_TEXTCAT
		textcat_Done(textcat);
#endif
		textcat = NULL;
	}
	_CLDELETE(index->default_analyzer);
	i_free(index->textcat_dir);
	i_free(index->textcat_conf);
	i_free(index->path);
	i_free(index);
}

void lucene_utf8_n_to_tchar(const unsigned char *src, size_t srcsize,
			    wchar_t *dest, size_t destsize)
{
	ARRAY_TYPE(unichars) dest_arr;
	buffer_t buf = { 0, 0, { 0, 0, 0, 0, 0 } };

	i_assert(sizeof(wchar_t) == sizeof(unichar_t));

	buffer_create_data(&buf, dest, sizeof(wchar_t) * destsize);
	array_create_from_buffer(&dest_arr, &buf, sizeof(wchar_t));
	if (uni_utf8_to_ucs4_n(src, srcsize, &dest_arr) < 0)
		i_unreached();
	i_assert(array_count(&dest_arr)+1 == destsize);
	dest[destsize-1] = 0;
}

static const wchar_t *t_lucene_utf8_to_tchar(const char *str)
{
	ARRAY_TYPE(unichars) dest_arr;
	const unichar_t *ret;

	i_assert(sizeof(wchar_t) == sizeof(unichar_t));

	t_array_init(&dest_arr, strlen(str) + 1);
	if (uni_utf8_to_ucs4(str, &dest_arr) < 0)
		i_unreached();
	(void)array_append_space(&dest_arr);
	ret = array_idx(&dest_arr, 0);
	return (const wchar_t *)ret;
}

void lucene_index_select_mailbox(struct lucene_index *index,
				 const wchar_t guid[MAILBOX_GUID_HEX_LENGTH])
{
	memcpy(index->mailbox_guid, guid,
	       MAILBOX_GUID_HEX_LENGTH * sizeof(wchar_t));
	index->mailbox_guid[MAILBOX_GUID_HEX_LENGTH] = '\0';
}

void lucene_index_unselect_mailbox(struct lucene_index *index)
{
	memset(index->mailbox_guid, 0, sizeof(index->mailbox_guid));
}

static void lucene_handle_error(struct lucene_index *index, CLuceneError &err,
				const char *msg)
{
	const char *what = err.what();

	i_error("lucene index %s: %s failed: %s", index->path, msg, what);
}

static int lucene_index_open(struct lucene_index *index)
{
	if (index->reader != NULL)
		return 1;

	if (!IndexReader::indexExists(index->path))
		return 0;

	try {
		index->reader = IndexReader::open(index->path);
	} catch (CLuceneError &err) {
		lucene_handle_error(index, err, "IndexReader::open()");
		return -1;
	}
	return 1;
}

static int lucene_index_open_search(struct lucene_index *index)
{
	int ret;

	if (index->searcher != NULL)
		return 1;

	if ((ret = lucene_index_open(index)) <= 0)
		return ret;

	index->searcher = _CLNEW IndexSearcher(index->reader);
	return 1;
}

static int
lucene_doc_get_uid(struct lucene_index *index, Document *doc, uint32_t *uid_r)
{
	Field *field = doc->getField(_T("uid"));
	const TCHAR *uid = field == NULL ? NULL : field->stringValue();
	if (uid == NULL) {
		i_error("lucene: Corrupted FTS index %s: No UID for document",
			index->path);
		return -1;
	}

	uint32_t num = 0;
	while (*uid != 0) {
		num = num*10 + (*uid - '0');
		uid++;
	}
	*uid_r = num;
	return 0;
}

int lucene_index_get_last_uid(struct lucene_index *index, uint32_t *last_uid_r)
{
	int ret = 0;

	*last_uid_r = 0;

	if ((ret = lucene_index_open_search(index)) <= 0)
		return ret;

	Term mailbox_term(_T("box"), index->mailbox_guid);
	TermQuery query(&mailbox_term);

	uint32_t last_uid = 0;
	try {
		Hits *hits = index->searcher->search(&query);

		for (size_t  i = 0; i < hits->length(); i++) {
			uint32_t uid;

			if (lucene_doc_get_uid(index, &hits->doc(i),
					       &uid) < 0) {
				ret = -1;
				break;
			}

			if (uid > last_uid)
				last_uid = uid;
		}
		_CLDELETE(hits);
	} catch (CLuceneError &err) {
		lucene_handle_error(index, err, "last_uid search");
		ret = -1;
	}
	*last_uid_r = last_uid;
	return ret;
}

int lucene_index_get_doc_count(struct lucene_index *index, uint32_t *count_r)
{
	int ret;

	if (index->reader == NULL) {
		lucene_index_close(index);
		if ((ret = lucene_index_open(index)) < 0)
			return -1;
		if (ret == 0) {
			*count_r = 0;
			return 0;
		}
	}
	*count_r = index->reader->numDocs();
	return 0;
}

int lucene_index_build_init(struct lucene_index *index)
{
	const char *lock_path;
	struct stat st;

	lucene_index_close(index);

	lock_path = t_strdup_printf("%s/write.lock", index->path);
	if (stat(lock_path, &st) == 0 &&
	    st.st_mtime < time(NULL) - LUCENE_LOCK_OVERRIDE_SECS) {
		if (unlink(lock_path) < 0)
			i_error("unlink(%s) failed: %m");
	}

	bool exists = IndexReader::indexExists(index->path);
	try {
		index->writer = _CLNEW IndexWriter(index->path,
						   index->default_analyzer,
						   !exists);
	} catch (CLuceneError &err) {
		lucene_handle_error(index, err, "IndexWriter()");
		return -1;
	}
	index->writer->setMaxFieldLength(MAX_TERMS_PER_DOCUMENT);
	return 0;
}

static Analyzer *get_analyzer(struct lucene_index *index, const char *lang)
{
	const struct lucene_analyzer *a;
	struct lucene_analyzer new_analyzer;
	Analyzer *analyzer;

	array_foreach(&index->analyzers, a) {
		if (strcmp(a->lang, lang) == 0)
			return a->analyzer;
	}

	memset(&new_analyzer, 0, sizeof(new_analyzer));
	new_analyzer.lang = i_strdup(lang);
	new_analyzer.analyzer = _CLNEW snowball::SnowballAnalyzer(lang);
	array_append_i(&index->analyzers.arr, &new_analyzer, 1);
	return new_analyzer.analyzer;
}

#ifdef HAVE_LUCENE_TEXTCAT
static Analyzer *
guess_analyzer(struct lucene_index *index, const void *data, size_t size)
{
	const char *lang;

	if (textcat_broken)
		return NULL;

	if (textcat == NULL) {
		textcat = index->textcat_conf == NULL ? NULL :
			special_textcat_Init(index->textcat_conf,
					     index->textcat_dir);
		if (textcat == NULL) {
			textcat_broken = TRUE;
			return NULL;
		}
	}

	/* try to guess the language */
	lang = textcat_Classify(textcat, (const char *)data,
				I_MIN(size, 500));
	const char *p = strchr(lang, ']');
	if (lang[0] != '[' || p == NULL)
		return NULL;
	lang = t_strdup_until(lang+1, p);
	if (strcmp(lang, DEFAULT_LANGUAGE) == 0)
		return index->default_analyzer;

	return get_analyzer(index, lang);
}
#else
static Analyzer *
guess_analyzer(struct lucene_index *index ATTR_UNUSED,
	       const void *data ATTR_UNUSED, size_t size ATTR_UNUSED)
{
	return NULL;
}
#endif

static int lucene_index_build_flush(struct lucene_index *index)
{
	int ret = 0;

	if (index->doc == NULL)
		return 0;

	try {
		index->writer->addDocument(index->doc,
					   index->cur_analyzer != NULL ?
					   index->cur_analyzer :
					   index->default_analyzer);
	} catch (CLuceneError &err) {
		lucene_handle_error(index, err, "IndexWriter::addDocument()");
		ret = -1;
	}

	_CLDELETE(index->doc);
	index->doc = NULL;
	index->cur_analyzer = NULL;
	return ret;
}

int lucene_index_build_more(struct lucene_index *index, uint32_t uid,
			    const unsigned char *data, size_t size,
			    const char *hdr_name)
{
	wchar_t id[MAX_INT_STRLEN];
	size_t namesize, datasize;

	if (uid != index->prev_uid) {
		if (lucene_index_build_flush(index) < 0)
			return -1;
		index->prev_uid = uid;

		index->doc = _CLNEW Document();
		swprintf(id, N_ELEMENTS(id), L"%u", uid);
		index->doc->add(*_CLNEW Field(_T("uid"), id, Field::STORE_YES | Field::INDEX_UNTOKENIZED));
		index->doc->add(*_CLNEW Field(_T("box"), index->mailbox_guid, Field::STORE_YES | Field::INDEX_UNTOKENIZED));
	}

	datasize = uni_utf8_strlen_n(data, size) + 1;
	wchar_t dest[datasize];
	lucene_utf8_n_to_tchar(data, size, dest, datasize);

	if (hdr_name != NULL) {
		/* hdr_name should be ASCII, but don't break in case it isn't */
		hdr_name = t_str_lcase(hdr_name);
		namesize = uni_utf8_strlen(hdr_name) + 1;
		wchar_t wname[namesize];
		lucene_utf8_n_to_tchar((const unsigned char *)hdr_name,
				       strlen(hdr_name), wname, namesize);
		index->doc->add(*_CLNEW Field(_T("hdr"), wname, Field::STORE_NO | Field::INDEX_UNTOKENIZED));
		index->doc->add(*_CLNEW Field(_T("hdr"), dest, Field::STORE_NO | Field::INDEX_TOKENIZED));

		if (fts_header_want_indexed(hdr_name))
			index->doc->add(*_CLNEW Field(wname, dest, Field::STORE_NO | Field::INDEX_TOKENIZED));
	} else if (size > 0) {
		if (index->cur_analyzer == NULL)
			index->cur_analyzer = guess_analyzer(index, data, size);
		index->doc->add(*_CLNEW Field(_T("body"), dest, Field::STORE_NO | Field::INDEX_TOKENIZED));
	}
	return 0;
}

int lucene_index_build_deinit(struct lucene_index *index)
{
	int ret = 0;

	if (index->prev_uid == 0) {
		/* no changes. */
		return 0;
	}
	index->prev_uid = 0;

	if (index->writer == NULL) {
		lucene_index_close(index);
		return -1;
	}

	if (lucene_index_build_flush(index) < 0)
		ret = -1;

	try {
		index->writer->close();
	} catch (CLuceneError &err) {
		lucene_handle_error(index, err, "IndexWriter::close()");
		ret = -1;
	}

	lucene_index_close(index);
	return ret;
}

static int
wcharguid_to_guid(mail_guid_128_t *dest, const wchar_t *src)
{
	buffer_t buf = { 0, 0, { 0, 0, 0, 0, 0 } };
	char src_chars[MAIL_GUID_128_SIZE*2 + 1];
	unsigned int i;

	for (i = 0; i < sizeof(src_chars)-1; i++) {
		if ((src[i] >= '0' && src[i] <= '9') ||
		    (src[i] >= 'a' && src[i] <= 'f'))
			src_chars[i] = src[i];
		else
			return -1;
	}
	if (src[i] != '\0')
		return -1;
	src_chars[i] = '\0';

	buffer_create_data(&buf, dest, sizeof(*dest));
	return hex_to_binary(src_chars, &buf);
}

static int
rescan_get_uids(struct mailbox *box, ARRAY_TYPE(seq_range) *uids)
{
	struct mailbox_status status;

	if (mailbox_get_status(box, STATUS_MESSAGES, &status) < 0)
		return -1;

	if (status.messages > 0) T_BEGIN {
		ARRAY_TYPE(seq_range) seqs;

		t_array_init(&seqs, 2);
		seq_range_array_add_range(&seqs, 1, status.messages);
		mailbox_get_uid_range(box, &seqs, uids);
	} T_END;
	return 0;
}

static int rescan_finish(struct rescan_context *ctx)
{
	int ret;

	ret = fts_index_set_last_uid(ctx->box, ctx->last_existing_uid);
	mailbox_free(&ctx->box);
	return ret;
}

static int
fts_lucene_get_mailbox_guid(struct lucene_index *index, Document *doc,
			    mail_guid_128_t *guid_r)
{
	Field *field = doc->getField(_T("box"));
	const TCHAR *box_guid = field == NULL ? NULL : field->stringValue();
	if (box_guid == NULL) {
		i_error("lucene: Corrupted FTS index %s: No mailbox for document",
			index->path);
		return -1;
	}

	if (wcharguid_to_guid(guid_r, box_guid) < 0) {
		i_error("lucene: Corrupted FTS index %s: "
			"box field not in expected format", index->path);
		return -1;
	}
	return 0;
}

static int
rescan_open_mailbox(struct rescan_context *ctx, Document *doc)
{
	mail_guid_128_t guid;
	int ret;

	if (fts_lucene_get_mailbox_guid(ctx->index, doc, &guid) < 0)
		return 0;

	if (memcmp(guid, ctx->box_guid, sizeof(guid)) == 0) {
		/* same as last one */
		return ctx->box_ret;
	}
	memcpy(ctx->box_guid, guid, sizeof(ctx->box_guid));

	if (ctx->box != NULL)
		rescan_finish(ctx);
	ctx->box = mailbox_alloc_guid(ctx->list, guid, MAILBOX_FLAG_KEEP_RECENT);
	if (mailbox_open(ctx->box) < 0) {
		enum mail_error error;
		const char *errstr;

		errstr = mailbox_get_last_error(ctx->box, &error);
		if (error == MAIL_ERROR_NOTFOUND)
			ret = 0;
		else {
			i_error("lucene: Couldn't open mailbox %s: %s",
				mailbox_get_vname(ctx->box), errstr);
			ret = -1;
		}
		mailbox_free(&ctx->box);
		ctx->box_ret = ret;
		return ret;
	}
	if (mailbox_sync(ctx->box, (enum mailbox_sync_flags)0) < 0) {
		i_error("lucene: Failed to sync mailbox %s: %s",
			mailbox_get_vname(ctx->box),
			mailbox_get_last_error(ctx->box, NULL));
		mailbox_free(&ctx->box);
		ctx->box_ret = -1;
		return -1;
	}

	array_clear(&ctx->uids);
	rescan_get_uids(ctx->box, &ctx->uids);

	ctx->warned = FALSE;
	ctx->last_existing_uid = 0;
	ctx->uids_iter_n = 0;
	seq_range_array_iter_init(&ctx->uids_iter, &ctx->uids);

	ctx->box_ret = 1;
	return 1;
}

static int
rescan_next(struct rescan_context *ctx, Document *doc)
{
	uint32_t lucene_uid, idx_uid;

	if (lucene_doc_get_uid(ctx->index, doc, &lucene_uid) < 0)
		return 0;

	if (seq_range_array_iter_nth(&ctx->uids_iter, ctx->uids_iter_n,
				     &idx_uid)) {
		if (idx_uid == lucene_uid) {
			ctx->uids_iter_n++;
			ctx->last_existing_uid = idx_uid;
			return 1;
		}
		if (idx_uid < lucene_uid) {
			/* lucene is missing an UID from the middle. delete
			   the rest of the messages from this mailbox and
			   reindex. */
			if (!ctx->warned) {
				i_warning("lucene: Mailbox %s "
					  "missing UIDs in the middle",
					  mailbox_get_vname(ctx->box));
				ctx->warned = TRUE;
			}
		} else {
			/* UID has been expunged from index. delete from
			   lucene as well. */
		}
		return 0;
	} else {
		/* the rest of the messages have been expunged from index */
		return 0;
	}
}

int lucene_index_rescan(struct lucene_index *index,
			struct mailbox_list *list)
{
	static const TCHAR *sort_fields[] = { _T("box"), _T("uid"), NULL };
	struct rescan_context ctx;
	mail_guid_128_t guid;
	bool failed = false;
	int ret;

	if ((ret = lucene_index_open_search(index)) <= 0)
		return ret;

	Term term(_T("box"), _T("*"));
	WildcardQuery query(&term);
	Sort sort(sort_fields);

	memset(&ctx, 0, sizeof(ctx));
	ctx.index = index;
	ctx.list = list;
	i_array_init(&ctx.uids, 128);

	try {
		Hits *hits = index->searcher->search(&query, &sort);

		for (size_t i = 0; i < hits->length(); i++) {
			ret = rescan_open_mailbox(&ctx, &hits->doc(i));
			if (ret > 0)
				ret = rescan_next(&ctx, &hits->doc(i));
			if (ret < 0)
				failed = true;
			else if (ret == 0)
				index->reader->deleteDocument(hits->id(i));
		}
		_CLDELETE(hits);
		index->reader->close();
		lucene_index_close(index);
	} catch (CLuceneError &err) {
		lucene_handle_error(index, err, "rescan search");
		failed = true;
	}
	if (ctx.box != NULL)
		rescan_finish(&ctx);
	array_free(&ctx.uids);
	return failed ? -1 : 0;
}

static void guid128_to_wguid(const mail_guid_128_t guid,
			     wchar_t wguid_hex[MAILBOX_GUID_HEX_LENGTH + 1])
{
	buffer_t buf = { 0, 0, { 0, 0, 0, 0, 0 } };
	unsigned char guid_hex[MAILBOX_GUID_HEX_LENGTH];
	unsigned int i;

	buffer_create_data(&buf, guid_hex, MAILBOX_GUID_HEX_LENGTH);
	binary_to_hex_append(&buf, guid, MAIL_GUID_128_SIZE);
	for (i = 0; i < MAILBOX_GUID_HEX_LENGTH; i++)
		wguid_hex[i] = guid_hex[i];
	wguid_hex[i] = '\0';
}

static int
lucene_index_expunge_record(struct lucene_index *index,
			    const struct fts_expunge_log_read_record *rec)
{
	const struct seq_range *range;
	unsigned int count;
	int ret;

	if ((ret = lucene_index_open_search(index)) <= 0)
		return ret;
	range = array_get(&rec->uids, &count);

	BooleanQuery query;

	/* search for UIDs between lowest and highest expunged UID */
	wchar_t wuid1[MAX_INT_STRLEN], wuid2[MAX_INT_STRLEN];
	swprintf(wuid1, N_ELEMENTS(wuid1), L"%u", range[0].seq1);
	swprintf(wuid2, N_ELEMENTS(wuid2), L"%u", range[count-1].seq2);
	Term wuid1_term(_T("uid"), wuid1);
	Term wuid2_term(_T("uid"), wuid2);
	RangeQuery rq(&wuid1_term, &wuid2_term, true);
	query.add(&rq, BooleanClause::MUST);

	wchar_t wguid[MAILBOX_GUID_HEX_LENGTH + 1];
	guid128_to_wguid(rec->mailbox_guid, wguid);
	Term term(_T("box"), wguid);
	TermQuery mailbox_query(&term);
	query.add(&mailbox_query, BooleanClause::MUST);

	try {
		Hits *hits = index->searcher->search(&query);

		for (size_t i = 0; i < hits->length(); i++) {
			uint32_t uid;

			if (lucene_doc_get_uid(index, &hits->doc(i),
					       &uid) < 0 ||
			    seq_range_exists(&rec->uids, uid))
				index->reader->deleteDocument(hits->id(i));
		}
		_CLDELETE(hits);
	} catch (CLuceneError &err) {
		lucene_handle_error(index, err, "expunge search");
		ret = -1;
	}
	return ret < 0 ? -1 : 0;
}

int lucene_index_expunge_from_log(struct lucene_index *index,
				  struct fts_expunge_log *log)
{
	struct fts_expunge_log_read_ctx *ctx;
	const struct fts_expunge_log_read_record *rec;
	int ret = 0, ret2;

	ctx = fts_expunge_log_read_begin(log);
	while ((rec = fts_expunge_log_read_next(ctx)) != NULL) {
		if (lucene_index_expunge_record(index, rec) < 0) {
			ret = -1;
			break;
		}
	}

	try {
		index->reader->close();
		lucene_index_close(index);
	} catch (CLuceneError &err) {
		lucene_handle_error(index, err, "expunge delete");
		ret = -1;
	}

	ret2 = fts_expunge_log_read_end(&ctx);
	if (ret < 0 || ret2 < 0)
		return -1;
	return ret2;
}

int lucene_index_optimize(struct lucene_index *index)
{
	int ret = 0;

	if (IndexReader::isLocked(index->path))
		IndexReader::unlock(index->path);

	IndexWriter *writer = NULL;
	try {
		writer = _CLNEW IndexWriter(index->path, index->default_analyzer, false);
		writer->optimize();
	} catch (CLuceneError &err) {
		lucene_handle_error(index, err, "IndexWriter::optimize()");
		ret = -1;
	}
	if (writer != NULL)
		_CLDELETE(writer);
	return ret;
}

// Mostly copy&pasted from CLucene's QueryParser
static Query* getFieldQuery(Analyzer *analyzer, const TCHAR* _field, const TCHAR* queryText, bool fuzzy) {
  // Use the analyzer to get all the tokens, and then build a TermQuery,
  // PhraseQuery, or nothing based on the term count

  StringReader reader(queryText);
  TokenStream* source = analyzer->tokenStream(_field, &reader);

  CLVector<CL_NS(analysis)::Token*, Deletor::Object<CL_NS(analysis)::Token> > v;
  CL_NS(analysis)::Token* t = NULL;
  int32_t positionCount = 0;
  bool severalTokensAtSamePosition = false;

  while (true) {
    t = _CLNEW Token();
    try {
      Token* _t = source->next(t);
      if (_t == NULL) _CLDELETE(t);
    }_CLCATCH_ERR(CL_ERR_IO, _CLLDELETE(source);_CLLDELETE(t);,{
      t = NULL;
    });
    if (t == NULL)
      break;
    v.push_back(t);
    if (t->getPositionIncrement() != 0)
      positionCount += t->getPositionIncrement();
    else
      severalTokensAtSamePosition = true;
  }
  try {
    source->close();
  }
  _CLCATCH_ERR_CLEANUP(CL_ERR_IO, {_CLLDELETE(source);_CLLDELETE(t);} ); /* cleanup */
  _CLLDELETE(source);

  if (v.size() == 0)
    return NULL;
  else if (v.size() == 1) {
    Term* tm = _CLNEW Term(_field, v.at(0)->termBuffer());
    Query* ret;
    if (fuzzy)
      ret = _CLNEW FuzzyQuery( tm );
    else
      ret = _CLNEW PrefixQuery( tm );
    _CLDECDELETE(tm);
    return ret;
  } else {
    if (severalTokensAtSamePosition) {
      if (positionCount == 1) {
        // no phrase query:
        BooleanQuery* q = _CLNEW BooleanQuery(true);
        for(size_t i=0; i<v.size(); i++ ){
          Term* tm = _CLNEW Term(_field, v.at(i)->termBuffer());
          q->add(_CLNEW TermQuery(tm), true, BooleanClause::SHOULD);
          _CLDECDELETE(tm);
        }
        return q;
      }else {
		    MultiPhraseQuery* mpq = _CLNEW MultiPhraseQuery();
		    CLArrayList<Term*> multiTerms;
		    int32_t position = -1;
		    for (size_t i = 0; i < v.size(); i++) {
			    t = v.at(i);
			    if (t->getPositionIncrement() > 0 && multiTerms.size() > 0) {
            ValueArray<Term*> termsArray(multiTerms.size());
            multiTerms.toArray(termsArray.values);
	    mpq->add(&termsArray,position);
				    multiTerms.clear();
			    }
			    position += t->getPositionIncrement();
			    multiTerms.push_back(_CLNEW Term(_field, t->termBuffer()));
		    }
        ValueArray<Term*> termsArray(multiTerms.size());
        multiTerms.toArray(termsArray.values);
	mpq->add(&termsArray,position);
		    return mpq;
      }
    }else {
      PhraseQuery* pq = _CLNEW PhraseQuery();
      int32_t position = -1;

      for (size_t i = 0; i < v.size(); i++) {
        t = v.at(i);
        Term* tm = _CLNEW Term(_field, t->termBuffer());
	position += t->getPositionIncrement();
	pq->add(tm,position);
        _CLDECDELETE(tm);
      }
      return pq;
    }
  }
}

static Query *
lucene_get_query(struct lucene_index *index,
		 const TCHAR *key, const struct mail_search_arg *arg)
{
	const TCHAR *wvalue = t_lucene_utf8_to_tchar(arg->value.str);
	Analyzer *analyzer = guess_analyzer(index, arg->value.str,
					    strlen(arg->value.str));
	if (analyzer == NULL)
		analyzer = index->default_analyzer;

	return getFieldQuery(analyzer, key, wvalue, arg->fuzzy);
}

static bool
lucene_add_definite_query(struct lucene_index *index, BooleanQuery &query,
			  struct mail_search_arg *arg, bool and_args)
{
	Query *q;

	if (arg->match_not && !and_args) {
		/* FIXME: we could handle this by doing multiple queries.. */
		return false;
	}

	switch (arg->type) {
	case SEARCH_TEXT: {
		BooleanQuery *bq = _CLNEW BooleanQuery();
		Query *q1 = lucene_get_query(index, _T("hdr"), arg);
		Query *q2 = lucene_get_query(index, _T("body"), arg);

		if (q1 == NULL && q2 == NULL)
			q = NULL;
		else {
			if (q1 != NULL)
				bq->add(q1, true, BooleanClause::SHOULD);
			if (q2 != NULL)
				bq->add(q2, true, BooleanClause::SHOULD);
			q = bq;
		}
		break;
	}
	case SEARCH_BODY:
		q = lucene_get_query(index, _T("body"), arg);
		break;
	case SEARCH_HEADER:
	case SEARCH_HEADER_ADDRESS:
	case SEARCH_HEADER_COMPRESS_LWSP:
		if (!fts_header_want_indexed(arg->hdr_field_name))
			return false;
		if (*arg->value.str == '\0') {
			/* FIXME: handle existence of a search key */
			return false;
		}

		q = lucene_get_query(index,
				     t_lucene_utf8_to_tchar(arg->hdr_field_name),
				     arg);
		break;
	default:
		return false;
	}

	if (q == NULL) {
		/* couldn't handle this search after all (e.g. trying to search
		   a stop word) */
		return false;
	}
	if (!and_args)
		query.add(q, true, BooleanClause::SHOULD);
	else if (!arg->match_not)
		query.add(q, true, BooleanClause::MUST);
	else
		query.add(q, true, BooleanClause::MUST_NOT);
	return true;
}

static bool
lucene_add_maybe_query(struct lucene_index *index, BooleanQuery &query,
		       struct mail_search_arg *arg, bool and_args)
{
	Query *q;

	if (arg->match_not && !and_args) {
		/* FIXME: we could handle this by doing multiple queries.. */
		return false;
	}

	switch (arg->type) {
	case SEARCH_HEADER:
	case SEARCH_HEADER_ADDRESS:
	case SEARCH_HEADER_COMPRESS_LWSP:
		if (fts_header_want_indexed(arg->hdr_field_name))
			return false;

		/* we can check if the search key exists in some header and
		   filter out the messages that have no chance of matching */
		q = lucene_get_query(index, _T("hdr"), arg);
		break;
	default:
		return false;
	}

	if (q == NULL) {
		/* couldn't handle this search after all (e.g. trying to search
		   a stop word) */
		return false;
	}
	if (!and_args)
		query.add(q, true, BooleanClause::SHOULD);
	else if (!arg->match_not)
		query.add(q, true, BooleanClause::MUST);
	else
		query.add(q, true, BooleanClause::MUST_NOT);
	return true;
}

static int
lucene_index_search(struct lucene_index *index,
		    Query &search_query, struct fts_result *result,
		    ARRAY_TYPE(seq_range) *uids_r)
{
	struct fts_score_map *score;
	int ret = 0;

	BooleanQuery query;
	query.add(&search_query, BooleanClause::MUST);

	Term mailbox_term(_T("box"), index->mailbox_guid);
	TermQuery mailbox_query(&mailbox_term);
	query.add(&mailbox_query, BooleanClause::MUST);

	try {
		Hits *hits = index->searcher->search(&query);

		uint32_t last_uid = 0;
		if (result != NULL)
			result->scores_sorted = true;

		for (size_t i = 0; i < hits->length(); i++) {
			uint32_t uid;

			if (lucene_doc_get_uid(index, &hits->doc(i),
					       &uid) < 0) {
				ret = -1;
				break;
			}

			if (result != NULL) {
				if (uid < last_uid)
					result->scores_sorted = false;
				last_uid = uid;

				seq_range_array_add(uids_r, 0, uid);
				score = array_append_space(&result->scores);
				score->uid = uid;
				score->score = hits->score(i);
			}
		}
		_CLDELETE(hits);
		return ret;
	} catch (CLuceneError &err) {
		lucene_handle_error(index, err, "search");
		return -1;
	}
}

int lucene_index_lookup(struct lucene_index *index,
			struct mail_search_arg *args, bool and_args,
			struct fts_result *result)
{
	struct mail_search_arg *arg;

	if (lucene_index_open_search(index) <= 0)
		return -1;

	BooleanQuery def_query;
	bool have_definites = false;

	for (arg = args; arg != NULL; arg = arg->next) {
		if (lucene_add_definite_query(index, def_query, arg, and_args)) {
			arg->match_always = true;
			have_definites = true;
		}
	}

	if (have_definites) {
		if (lucene_index_search(index, def_query, result,
					&result->definite_uids) < 0)
			return -1;
	}

	BooleanQuery maybe_query;
	bool have_maybies = false;

	for (arg = args; arg != NULL; arg = arg->next) {
		if (lucene_add_maybe_query(index, maybe_query, arg, and_args)) {
			arg->match_always = true;
			have_maybies = true;
		}
	}

	if (have_maybies) {
		if (lucene_index_search(index, maybe_query, NULL,
					&result->maybe_uids) < 0)
			return -1;
	}
	return 0;
}

static int
lucene_index_search_multi(struct lucene_index *index, struct hash_table *guids,
			  Query &search_query, struct fts_multi_result *result)
{
	struct fts_score_map *score;
	int ret = 0;

	BooleanQuery query;
	query.add(&search_query, BooleanClause::MUST);

	BooleanQuery mailbox_query;
	struct hash_iterate_context *iter;
	void *key, *value;
	iter = hash_table_iterate_init(guids);
	while (hash_table_iterate(iter, &key, &value)) {
		Term *term = _CLNEW Term(_T("box"), (wchar_t *)key);
		TermQuery *q = _CLNEW TermQuery(term);
		mailbox_query.add(q, true, BooleanClause::SHOULD);
	}
	hash_table_iterate_deinit(&iter);

	query.add(&mailbox_query, BooleanClause::MUST);
	try {
		Hits *hits = index->searcher->search(&query);

		for (size_t i = 0; i < hits->length(); i++) {
			uint32_t uid;

			Field *field = hits->doc(i).getField(_T("box"));
			const TCHAR *box_guid = field == NULL ? NULL : field->stringValue();
			if (box_guid == NULL) {
				i_error("lucene: Corrupted FTS index %s: No mailbox for document",
					index->path);
				ret = -1;
				break;
			}
			struct fts_result *br = (struct fts_result *)
				hash_table_lookup(guids, (const void *)box_guid);
			if (br == NULL) {
				i_warning("lucene: Returned unexpected mailbox with GUID %ls", box_guid);
				continue;
			}

			if (lucene_doc_get_uid(index, &hits->doc(i),
					       &uid) < 0) {
				ret = -1;
				break;
			}

			if (!array_is_created(&br->definite_uids)) {
				p_array_init(&br->definite_uids, result->pool, 32);
				p_array_init(&br->scores, result->pool, 32);
			}
			seq_range_array_add(&br->definite_uids, 0, uid);
			score = array_append_space(&br->scores);
			score->uid = uid;
			score->score = hits->score(i);
		}
		_CLDELETE(hits);
		return ret;
	} catch (CLuceneError &err) {
		lucene_handle_error(index, err, "multi search");
		return -1;
	}
}

int lucene_index_lookup_multi(struct lucene_index *index,
			      struct hash_table *guids,
			      struct mail_search_arg *args, bool and_args,
			      struct fts_multi_result *result)
{
	struct mail_search_arg *arg;

	if (lucene_index_open_search(index) <= 0)
		return -1;

	BooleanQuery def_query;
	bool have_definites = false;

	for (arg = args; arg != NULL; arg = arg->next) {
		if (lucene_add_definite_query(index, def_query, arg, and_args)) {
			arg->match_always = true;
			have_definites = true;
		}
	}

	if (have_definites) {
		if (lucene_index_search_multi(index, guids,
					      def_query, result) < 0)
			return -1;
	}
	return 0;
}

struct lucene_index_iter {
	struct lucene_index *index;
	struct lucene_index_record rec;

	Term *term;
	WildcardQuery *query;
	Sort *sort;

	Hits *hits;
	size_t i;
	bool failed;
};

struct lucene_index_iter *
lucene_index_iter_init(struct lucene_index *index)
{
	static const TCHAR *sort_fields[] = { _T("box"), _T("uid"), NULL };
	struct lucene_index_iter *iter;
	int ret;

	iter = i_new(struct lucene_index_iter, 1);
	iter->index = index;
	if ((ret = lucene_index_open_search(index)) <= 0) {
		if (ret < 0)
			iter->failed = true;
		return iter;
	}

	iter->term = _CLNEW Term(_T("box"), _T("*"));
	iter->query = _CLNEW WildcardQuery(iter->term);
	iter->sort = _CLNEW Sort(sort_fields);

	try {
		iter->hits = index->searcher->search(iter->query, iter->sort);
	} catch (CLuceneError &err) {
		lucene_handle_error(index, err, "rescan search");
		iter->failed = true;
	}
	return iter;
}

const struct lucene_index_record *
lucene_index_iter_next(struct lucene_index_iter *iter)
{
	if (iter->hits == NULL)
		return NULL;
	if (iter->i == iter->hits->length())
		return NULL;

	Document *doc = &iter->hits->doc(iter->i);
	iter->i++;

	memset(&iter->rec, 0, sizeof(iter->rec));
	(void)fts_lucene_get_mailbox_guid(iter->index, doc,
					  &iter->rec.mailbox_guid);
	(void)lucene_doc_get_uid(iter->index, doc, &iter->rec.uid);
	return &iter->rec;
}

int lucene_index_iter_deinit(struct lucene_index_iter **_iter)
{
	struct lucene_index_iter *iter = *_iter;
	int ret = iter->failed ? -1 : 0;

	*_iter = NULL;
	if (iter->hits != NULL)
		_CLDELETE(iter->hits);
	if (iter->query != NULL) {
		_CLDELETE(iter->query);
		_CLDELETE(iter->sort);
		_CLDELETE(iter->term);
	}
	i_free(iter);
	return ret;
}
