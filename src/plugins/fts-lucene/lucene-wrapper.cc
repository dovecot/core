/* Copyright (C) 2006 Timo Sirainen */

extern "C" {
#include "lib.h"
#include "str-sanitize.h"
#include "lucene-wrapper.h"
};
#include <CLucene.h>

/* Lucene's default is 10000. Use it here also.. */
#define MAX_TERMS_PER_DOCUMENT 10000

using namespace lucene::document;
using namespace lucene::index;
using namespace lucene::search;
using namespace lucene::queryParser;
using namespace lucene::analysis;

struct lucene_index {
	char *path;
	char *mailbox_name;
	TCHAR *tmailbox_name;

	IndexReader *reader;
	IndexWriter *writer;
	IndexSearcher *searcher;
	Analyzer *analyzer;

	Document *doc;
	uint32_t prev_uid, last_uid;
	int32_t last_uid_doc_id;
};

static const uint8_t utf8_skip_table[256] = {
	1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
	1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
	1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
	1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
	1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
	1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
	2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,
	3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,4,4,4,4,4,4,4,4,5,5,5,5,6,6,1,1
};

class RawTokenStream : public TokenStream {
	CL_NS(util)::Reader *reader;

public:
	RawTokenStream(CL_NS(util)::Reader *reader) {
		this->reader = reader;
	};

	bool next(Token *token) {
		const TCHAR *data;

		int32_t len = this->reader->read(data);
		if (len <= 0)
			return false;

		token->set(data, 0, len);
		return true;
	}

	void close() { }
};

class DovecotAnalyzer : public standard::StandardAnalyzer {
public:
	TokenStream *tokenStream(const TCHAR *fieldName,
				 CL_NS(util)::Reader *reader) {
		if (fieldName != 0 && wcscmp(fieldName, L"contents") != 0)
			return _CLNEW RawTokenStream(reader);
		return standard::StandardAnalyzer::
			tokenStream(fieldName, reader);
	}
};

struct lucene_index *lucene_index_init(const char *path)
{
	struct lucene_index *index;

	index = i_new(struct lucene_index, 1);
	index->path = i_strdup(path);
	return index;
}

static void lucene_index_close(struct lucene_index *index)
{
	_CLDELETE(index->reader);
	_CLDELETE(index->writer);
	_CLDELETE(index->searcher);
	_CLDELETE(index->analyzer);
}

void lucene_index_deinit(struct lucene_index *index)
{
	lucene_index_close(index);
	i_free(index->mailbox_name);
	i_free(index->tmailbox_name);
	i_free(index);
}

int lucene_index_select_mailbox(struct lucene_index *index,
				const char *mailbox_name)
{
	size_t len;

	i_free(index->mailbox_name);
	i_free(index->tmailbox_name);

	len = strlen(mailbox_name);
	index->mailbox_name = i_strdup(mailbox_name);
	index->tmailbox_name = i_new(TCHAR, len + 1);
	STRCPY_AtoT(index->tmailbox_name, mailbox_name, len);
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
		i_error("lucene: IndexReader::open(%s): %s", index->path, err.what());
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

	if (index->analyzer == NULL)
		index->analyzer = _CLNEW DovecotAnalyzer();

	index->searcher = _CLNEW IndexSearcher(index->reader);
	return 1;
}

static int lucene_doc_get_uid(struct lucene_index *index,
			      Document *doc, uint32_t *uid_r)
{
	Field *field = doc->getField(_T("uid"));
	TCHAR *uid = field == NULL ? NULL : field->stringValue();
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

static int
lucene_index_get_last_uid(struct lucene_index *index)
{
	int ret = 0;

	index->last_uid = 0;
	index->last_uid_doc_id = -1;

	if (lucene_index_open_search(index) <= 0)
		return -1;

	Term mailbox_term(_T("box"), index->tmailbox_name);
	Term last_uid_term(_T("last_uid"), _T("1"));
	TermQuery mailbox_query(&mailbox_term);
	TermQuery last_uid_query(&last_uid_term);

	BooleanQuery query;
	query.add(&mailbox_query, true, false);
	query.add(&last_uid_query, true, false);

	try {
		Hits *hits = index->searcher->search(&query);

		if (hits->length() > 1) {
			i_error("lucene: last_uid search for mailbox %s "
				"returned multiple hits", index->mailbox_name);
		}
		for (int32_t i = 0; i < hits->length(); i++) {
			uint32_t uid;

			if (lucene_doc_get_uid(index, &hits->doc(i),
					       &uid) < 0) {
				ret = -1;
				break;
			}

			int32_t del_id = -1;
			if (uid > index->last_uid) {
				if (index->last_uid_doc_id >= 0)
					del_id = index->last_uid_doc_id;
				index->last_uid = uid;
				index->last_uid_doc_id = hits->id(i);
			} else {
				del_id = hits->id(i);
			}
			/*if (del_id >= 0)
				index->reader->deleteDocument(del_id);*/
		}
		_CLDELETE(hits);
	} catch (CLuceneError &err) {
		i_error("lucene: last_uid search failed: %s", err.what());
		ret = -1;
	}

	return ret;
}

int lucene_index_build_init(struct lucene_index *index, uint32_t *last_uid_r)
{
	uint32_t last_uid = 0;

	i_assert(index->mailbox_name != NULL);

	lucene_index_close(index);
	if (lucene_index_open(index) < 0)
		return -1;

	if (index->reader == NULL) {
		index->last_uid = 0;
		index->last_uid_doc_id = -1;
	} else {
		if (lucene_index_get_last_uid(index) < 0)
			return -1;
	}
	*last_uid_r = index->last_uid;

	if (index->writer != NULL)
		return 0;

	bool exists = IndexReader::indexExists(index->path);
	index->analyzer = _CLNEW DovecotAnalyzer();
	try {
		index->writer = _CLNEW IndexWriter(index->path,
						   index->analyzer, !exists);
	} catch (CLuceneError &err) {
		i_error("lucene: IndexWriter(%s) failed: %s",
			index->path, err.what());
		return -1;
	}

	index->writer->setMaxFieldLength(MAX_TERMS_PER_DOCUMENT);
	return 0;
}

static unsigned int utf8_strlen_n(const void *datap, size_t size)
{
	const unsigned char *data = (const unsigned char *)datap;
	const unsigned char *end = data + size;
	unsigned int skip, len = 0;
	size_t i;

	for (i = 0; i < size && data[i] != '\0'; ) {
		i += utf8_skip_table[data[i] & 0xff];
		i_assert(i <= size);
		len++;
	}
	return len;
}

static int lucene_index_build_flush(struct lucene_index *index)
{
	int ret = 0;

	if (index->doc == NULL)
		return 0;

	try {
		index->writer->addDocument(index->doc);
	} catch (CLuceneError &err) {
		i_error("lucene: IndexWriter::addDocument(%s) failed: %s",
			index->path, err.what());
		ret = -1;
	}

	_CLDELETE(index->doc);
	index->doc = NULL;
	return ret;
}

int lucene_index_build_more(struct lucene_index *index, uint32_t uid,
			    const unsigned char *data, size_t size)
{
	unsigned int len;
	char id[MAX_INT_STRLEN];

	i_assert(uid > index->last_uid);
	i_assert(size > 0);

	len = utf8_strlen_n(data, size);
	wchar_t dest[len+1];
	lucene_utf8towcs(dest, (const char *)data, len + 1);

	if (uid != index->prev_uid) {
		char id[MAX_INT_STRLEN];
		TCHAR tid[MAX_INT_STRLEN];

		if (lucene_index_build_flush(index) < 0)
			return -1;
		index->prev_uid = uid;

		index->doc = _CLNEW Document();
		i_snprintf(id, sizeof(id), "%u", uid);
		STRCPY_AtoT(tid, id, MAX_INT_STRLEN);
		index->doc->add(*Field::Text(_T("uid"), tid));
		index->doc->add(*Field::Text(_T("box"), index->tmailbox_name));
	}

	index->doc->add(*Field::Text(_T("contents"), dest));
	index->writer->addDocument(index->doc);
	return 0;
}

static int lucene_index_update_last_uid(struct lucene_index *index)
{
	Document doc;
	char id[MAX_INT_STRLEN];
	TCHAR tid[MAX_INT_STRLEN];

	i_snprintf(id, sizeof(id), "%u", index->last_uid);
	STRCPY_AtoT(tid, id, MAX_INT_STRLEN);

	doc.add(*Field::Text(_T("last_uid"), _T("1")));
	doc.add(*Field::Text(_T("uid"), tid));
	doc.add(*Field::Text(_T("box"), index->tmailbox_name));

	try {
		if (index->last_uid_doc_id >= 0) {
			//index->reader->deleteDocument(index->last_uid_doc_id);
			index->last_uid_doc_id = -1;
		}
	} catch (CLuceneError &err) {
		i_error("lucene: IndexWriter::deleteDocument(%s) failed: %s",
			index->path, err.what());
		return -1;
	}

	try {
		index->writer->addDocument(&doc);
		return 0;
	} catch (CLuceneError &err) {
		i_error("lucene: IndexWriter::addDocument(%s) failed: %s",
			index->path, err.what());
		return -1;
	}
}

int lucene_index_build_deinit(struct lucene_index *index)
{
	int ret = 0;

	if (index->prev_uid == 0) {
		/* no changes. */
		return 0;
	}

	if (index->prev_uid > index->last_uid)
		index->last_uid = index->prev_uid;
	index->prev_uid = 0;

	if (index->writer == NULL) {
		lucene_index_close(index);
		return -1;
	}

	if (lucene_index_build_flush(index) < 0)
		ret = -1;
	if (lucene_index_update_last_uid(index) < 0)
		ret = -1;

	try {
		index->writer->optimize();
	} catch (CLuceneError &err) {
		i_error("lucene: IndexWriter::optimize(%s) failed: %s",
			index->path, err.what());
		ret = -1;
	}
	try {
		index->writer->close();
	} catch (CLuceneError &err) {
		i_error("lucene: IndexWriter::close(%s) failed: %s",
			index->path, err.what());
		ret = -1;
	}

	lucene_index_close(index);
	return ret;
}

int lucene_index_lookup(struct lucene_index *index, const char *key,
			ARRAY_TYPE(seq_range) *result)
{
	const char *quoted_key;
	int ret = 0;

	if (lucene_index_open_search(index) <= 0)
		return -1;

	t_push();
	quoted_key = strchr(key, ' ') == NULL ?
		t_strdup_printf("%s*", key) :
		t_strdup_printf("\"%s\"", key);
	unsigned int len = utf8_strlen_n(quoted_key, (size_t)-1);
	wchar_t tkey[len + 1];
	lucene_utf8towcs(tkey, quoted_key, len + 1);
	t_pop();

	Query *content_query = NULL;
	try {
		content_query = QueryParser::parse(tkey, _T("contents"),
						   index->analyzer);
	} catch (CLuceneError &err) {
		if (getenv("DEBUG") != NULL) {
			i_info("lucene: QueryParser::parse(%s) failed: %s",
			       str_sanitize(key, 40), err.what());
		}
		lucene_index_close(index);
		return -1;
	}

	BooleanQuery query;
	Term mailbox_term(_T("box"), index->tmailbox_name);
	TermQuery mailbox_query(&mailbox_term);
	query.add(content_query, true, false);
	query.add(&mailbox_query, true, false);

	try {
		Hits *hits = index->searcher->search(&query);

		for (int32_t i = 0; i < hits->length(); i++) {
			uint32_t uid;

			if (lucene_doc_get_uid(index, &hits->doc(i),
					       &uid) < 0) {
				ret = -1;
				break;
			}

			seq_range_array_add(result, 0, uid);
		}
		_CLDELETE(hits);
	} catch (CLuceneError &err) {
		i_error("lucene: search(%s) failed: %s",
			index->path, err.what());
		ret = -1;
	}

	_CLDELETE(content_query);
	return ret;
}

int lucene_index_filter(struct lucene_index *index, const char *key,
			ARRAY_TYPE(seq_range) *result)
{
	/* FIXME: implement */
	return -1;
}
