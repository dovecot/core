/* Copyright (c) 2006-2010 Dovecot authors, see the included COPYING file */

extern "C" {
#include "lib.h"
#include "array.h"
#include "env-util.h"
#include "unichar.h"
#include "hash.h"
#include "str.h"
#include "strescape.h"
#include "mail-search.h"
#include "lucene-wrapper.h"

#include <dirent.h>
#include <sys/stat.h>
};
#include <CLucene.h>
#include <CLucene/util/CLStreams.h>
#include <CLucene/search/MultiPhraseQuery.h>

/* Lucene's default is 10000. Use it here also.. */
#define MAX_TERMS_PER_DOCUMENT 10000

#define LUCENE_LOCK_OVERRIDE_SECS 60

using namespace lucene::document;
using namespace lucene::index;
using namespace lucene::search;
using namespace lucene::queryParser;
using namespace lucene::analysis;
using namespace lucene::analysis;
using namespace lucene::util;

struct lucene_index {
	char *path;
	wchar_t mailbox_guid[MAILBOX_GUID_HEX_LENGTH + 1];

	IndexReader *reader;
	IndexWriter *writer;
	IndexSearcher *searcher;
	Analyzer *analyzer;

	Document *doc;
	uint32_t prev_uid;
};

struct lucene_index *lucene_index_init(const char *path)
{
	struct lucene_index *index;

	index = i_new(struct lucene_index, 1);
	index->path = i_strdup(path);
	index->analyzer = _CLNEW standard::StandardAnalyzer();
	return index;
}

static void lucene_index_close(struct lucene_index *index)
{
	_CLDELETE(index->reader);
	_CLDELETE(index->writer);
	_CLDELETE(index->searcher);
}

void lucene_index_deinit(struct lucene_index *index)
{
	lucene_index_close(index);
	_CLDELETE(index->analyzer);
	i_free(index->path);
	i_free(index);
}

static void
lucene_utf8_n_to_tchar(const unsigned char *src, size_t srcsize,
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
lucene_doc_get_uid(struct lucene_index *index, Document *doc,
		   const TCHAR *field_name, uint32_t *uid_r)
{
	Field *field = doc->getField(field_name);
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
					       _T("uid"), &uid) < 0) {
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
	return index->reader->numDocs();
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
						   index->analyzer, !exists);
	} catch (CLuceneError &err) {
		lucene_handle_error(index, err, "IndexWriter()");
		return -1;
	}
	index->writer->setMaxFieldLength(MAX_TERMS_PER_DOCUMENT);
	return 0;
}

static int lucene_index_build_flush(struct lucene_index *index)
{
	int ret = 0;

	if (index->doc == NULL)
		return 0;

	try {
		index->writer->addDocument(index->doc);
	} catch (CLuceneError &err) {
		lucene_handle_error(index, err, "IndexWriter::addDocument()");
		ret = -1;
	}

	_CLDELETE(index->doc);
	index->doc = NULL;
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
		namesize = uni_utf8_strlen(hdr_name) + 1;
		wchar_t wname[namesize];
		lucene_utf8_n_to_tchar((const unsigned char *)hdr_name,
				       strlen(hdr_name), wname, namesize);
		index->doc->add(*_CLNEW Field(_T("hdr"), wname, Field::STORE_NO | Field::INDEX_UNTOKENIZED));
		index->doc->add(*_CLNEW Field(_T("hdr"), dest, Field::STORE_NO | Field::INDEX_TOKENIZED));

		if (fts_header_want_indexed(hdr_name))
			index->doc->add(*_CLNEW Field(wname, dest, Field::STORE_NO | Field::INDEX_TOKENIZED));
	} else if (size > 0) {
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
		index->writer->optimize();
	} catch (CLuceneError &err) {
		lucene_handle_error(index, err, "IndexWriter::optimize()");
		ret = -1;
	}
	try {
		index->writer->close();
	} catch (CLuceneError &err) {
		lucene_handle_error(index, err, "IndexWriter::close()");
		ret = -1;
	}

	lucene_index_close(index);
	return ret;
}

struct uid_id_map {
	uint32_t imap_uid;
	int32_t lucene_id;
};
ARRAY_DEFINE_TYPE(uid_id_map, struct uid_id_map);

static int uid_id_map_cmp(const struct uid_id_map *u1,
			  const struct uid_id_map *u2)
{
	if (u1->imap_uid < u2->imap_uid)
		return -1;
	if (u1->imap_uid > u2->imap_uid)
		return 1;
	return 0;
}

static int get_mailbox_uid_id_map(struct lucene_index *index,
				  ARRAY_TYPE(uid_id_map) *uid_id_map)
{
	int ret = 0;

	/* get a sorted map of imap uid -> lucene id */
	Term mailbox_term(_T("box"), index->mailbox_guid);
	TermQuery query(&mailbox_term);

	try {
		Hits *hits = index->searcher->search(&query);

		for (size_t i = 0; i < hits->length(); i++) {
			uint32_t uid;

			if (lucene_doc_get_uid(index, &hits->doc(i),
					       _T("uid"), &uid) < 0) {
				ret = -1;
				break;
			}
			struct uid_id_map *ui = array_append_space(uid_id_map);
			ui->imap_uid = uid;
			ui->lucene_id = hits->id(i);
		}
		_CLDELETE(hits);
	} catch (CLuceneError &err) {
		lucene_handle_error(index, err, "expunge search");
		ret = -1;
	}

	array_sort(uid_id_map, uid_id_map_cmp);
	return ret;
}

int lucene_index_optimize_scan(struct lucene_index *index,
			       const ARRAY_TYPE(seq_range) *existing_uids,
			       ARRAY_TYPE(seq_range) *missing_uids_r)
{
	ARRAY_TYPE(uid_id_map) uid_id_map_arr;
	const struct uid_id_map *uid_id_map;
	struct seq_range_iter iter;
	unsigned int n, i, count;
	uint32_t uid;
	int ret;

	if ((ret = lucene_index_open_search(index)) <= 0) {
		if (ret < 0)
			return -1;

		/* index has been deleted, everything is missing */
		seq_range_array_merge(missing_uids_r, existing_uids);
		return 0;
	}

	i_array_init(&uid_id_map_arr, 128);
	if (get_mailbox_uid_id_map(index, &uid_id_map_arr) < 0)
		return -1;
	uid_id_map = array_get(&uid_id_map_arr, &count);

	seq_range_array_iter_init(&iter, existing_uids); n = i = 0;
	while (seq_range_array_iter_nth(&iter, n++, &uid)) {
		while (i < count && uid_id_map[i].imap_uid < uid) {
			/* expunged message */
			index->reader->deleteDocument(uid_id_map[i].lucene_id);
			i++;
		}

		if (i == count || uid_id_map[i].imap_uid > uid) {
			/* uid is missing from index */
			seq_range_array_add(missing_uids_r, 0, uid);
		} else {
			i++;
		}
	}
	for (; i < count; i++)
		index->reader->deleteDocument(uid_id_map[i].lucene_id);

	array_free(&uid_id_map_arr);
	return ret;
}

int lucene_index_optimize_finish(struct lucene_index *index)
{
	int ret = 0;

	if (IndexReader::isLocked(index->path))
		IndexReader::unlock(index->path);

	IndexWriter *writer = NULL;
	try {
		writer = _CLNEW IndexWriter(index->path, index->analyzer, false);
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
	return getFieldQuery(index->analyzer, key, wvalue, arg->fuzzy);
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

		bq->add(q1, true, BooleanClause::SHOULD);
		bq->add(q2, true, BooleanClause::SHOULD);
		q = bq;
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

		q = lucene_get_query(index,
				     t_lucene_utf8_to_tchar(arg->hdr_field_name),
				     arg);
		break;
	default:
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
					       _T("uid"), &uid) < 0) {
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
					       _T("uid"), &uid) < 0) {
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
