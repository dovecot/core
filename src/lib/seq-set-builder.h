#ifndef SEQ_SET_BUILDER_H
#define SEQ_SET_BUILDER_H

/* Append a seqset to the given string. */
struct seqset_builder *seqset_builder_init(string_t *str);
/* Add seq to the string. The string must not have been modified before the previous
   seqset_builder_add() call, since the last sequence in it may be rewritten. */
void seqset_builder_add(struct seqset_builder *builder, uint32_t seq);
/* Add the seq to the string, but only if the string length stays below max_len.
   Returns TRUE if added, FALSE if not. */
bool seqset_builder_try_add(struct seqset_builder *builder, size_t max_len, uint32_t seq);
/* Deinitialize the builder */
void seqset_builder_deinit(struct seqset_builder **builder);

#endif
