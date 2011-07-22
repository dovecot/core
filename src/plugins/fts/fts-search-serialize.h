#ifndef FTS_SEARCH_SERIALIZE_H
#define FTS_SEARCH_SERIALIZE_H

/* serialize [non]match_always fields (clearing buffer) */
void fts_search_serialize(buffer_t *buf, const struct mail_search_arg *args);
/* add/remove [non]match_always fields in search args */
void fts_search_deserialize(struct mail_search_arg *args,
			    const buffer_t *buf);
/* add match_always=TRUE fields to search args */
void fts_search_deserialize_add_matches(struct mail_search_arg *args,
					const buffer_t *buf);
/* add nonmatch_always=TRUE fields to search args */
void fts_search_deserialize_add_nonmatches(struct mail_search_arg *args,
					   const buffer_t *buf);

#endif
