/*------------------------------------------------------------------------------
* Copyright (C) 2003-2006 Ben van Klinken and the CLucene Team
*
* Distributable under the terms of either the Apache License (Version 2.0) or
* the GNU Lesser General Public License, as specified in the COPYING file.
------------------------------------------------------------------------------*/
#include <CLucene.h>
#include "SnowballAnalyzer.h"
#include "SnowballFilter.h"
#include <CLucene/util/CLStreams.h>
#include <CLucene/analysis/Analyzers.h>
#include <CLucene/analysis/standard/StandardTokenizer.h>
#include <CLucene/analysis/standard/StandardFilter.h>

extern "C" {
#include "lib.h"
#include "buffer.h"
#include "unichar.h"
#include "lucene-wrapper.h"
};

CL_NS_USE(analysis)
CL_NS_USE(util)
CL_NS_USE2(analysis,standard)

CL_NS_DEF2(analysis,snowball)

  /** Builds the named analyzer with no stop words. */
  SnowballAnalyzer::SnowballAnalyzer(normalizer_func_t *normalizer, const char* language) {
    this->language = strdup(language);
	this->normalizer = normalizer;
	stopSet = NULL;
    prevstream = NULL;
  }

  SnowballAnalyzer::~SnowballAnalyzer(){
	  if (prevstream) _CLDELETE(prevstream);
	  _CLDELETE_CARRAY(language);
	  if ( stopSet != NULL )
		  _CLDELETE(stopSet);
  }

  /** Builds the named analyzer with the given stop words.
  */
  SnowballAnalyzer::SnowballAnalyzer(const char* language, const TCHAR** stopWords) {
    this->language = strdup(language);

    stopSet = _CLNEW CLTCSetList(true);
	StopFilter::fillStopTable(stopSet,stopWords);
  }

  TokenStream* SnowballAnalyzer::tokenStream(const TCHAR* fieldName, CL_NS(util)::Reader* reader) {
	 return this->tokenStream(fieldName,reader,false);
  }

  /** Constructs a {@link StandardTokenizer} filtered by a {@link
      StandardFilter}, a {@link LowerCaseFilter} and a {@link StopFilter}. */
  TokenStream* SnowballAnalyzer::tokenStream(const TCHAR* fieldName, CL_NS(util)::Reader* reader, bool deleteReader) {
		BufferedReader* bufferedReader = reader->__asBufferedReader();
		TokenStream* result;

		if ( bufferedReader == NULL )
			result =  _CLNEW StandardTokenizer( _CLNEW FilteredBufferedReader(reader, deleteReader), true );
		else
			result = _CLNEW StandardTokenizer(bufferedReader, deleteReader);

	 result = _CLNEW StandardFilter(result, true);
    result = _CLNEW CL_NS(analysis)::LowerCaseFilter(result, true);
    if (stopSet != NULL)
      result = _CLNEW CL_NS(analysis)::StopFilter(result, true, stopSet);
    result = _CLNEW SnowballFilter(result, normalizer, language, true);
    return result;
  }
  
  TokenStream* SnowballAnalyzer::reusableTokenStream(const TCHAR* fieldName, CL_NS(util)::Reader* reader) {
      if (prevstream) _CLDELETE(prevstream);
      prevstream = this->tokenStream(fieldName, reader);
      return prevstream;
  }
  
  
  
  
  
  
    /** Construct the named stemming filter.
   *
   * @param in the input tokens to stem
   * @param name the name of a stemmer
   */
	SnowballFilter::SnowballFilter(TokenStream* in, normalizer_func_t *normalizer, const char* language, bool deleteTS):
		TokenFilter(in,deleteTS)
	{
		stemmer = sb_stemmer_new(language, NULL); //use utf8 encoding
		this->normalizer = normalizer;

		if ( stemmer == NULL ){
			_CLTHROWA(CL_ERR_IllegalArgument, "language not available for stemming\n"); //todo: richer error
		}
    }

	SnowballFilter::~SnowballFilter(){
		sb_stemmer_delete(stemmer);
	}

  /** Returns the next input Token, after being stemmed */
  Token* SnowballFilter::next(Token* token){
    if (input->next(token) == NULL)
      return NULL;

	unsigned char utf8text[LUCENE_MAX_WORD_LEN*5+1];
	unsigned int len = I_MIN(LUCENE_MAX_WORD_LEN, token->termLength());

	buffer_t buf = { 0, 0, { 0, 0, 0, 0, 0 } };
	i_assert(sizeof(wchar_t) == sizeof(unichar_t));
	buffer_create_from_data(&buf, utf8text, sizeof(utf8text));
	uni_ucs4_to_utf8((const unichar_t *)token->termBuffer(), len, &buf);

    const sb_symbol* stemmed = sb_stemmer_stem(stemmer, utf8text, buf.used);
	if ( stemmed == NULL )
		_CLTHROWA(CL_ERR_Runtime,"Out of memory");

	int stemmedLen=sb_stemmer_length(stemmer);

	if (normalizer == NULL) {
	  unsigned int tchartext_size =
			  uni_utf8_strlen_n(stemmed, stemmedLen) + 1;
	  TCHAR tchartext[tchartext_size];
	  lucene_utf8_n_to_tchar(stemmed, stemmedLen, tchartext, tchartext_size);
	  token->set(tchartext,token->startOffset(), token->endOffset(), token->type());
	} else T_BEGIN {
	  buffer_t *norm_buf = buffer_create_dynamic(pool_datastack_create(),
												 stemmedLen);
	  normalizer(stemmed, stemmedLen, norm_buf);

	  unsigned int tchartext_size =
			  uni_utf8_strlen_n(norm_buf->data, norm_buf->used) + 1;
	  TCHAR tchartext[tchartext_size];
	  lucene_utf8_n_to_tchar((const unsigned char *)norm_buf->data,
							 norm_buf->used, tchartext, tchartext_size);
	  token->set(tchartext,token->startOffset(), token->endOffset(), token->type());
	} T_END;
	return token;
  }


CL_NS_END2
