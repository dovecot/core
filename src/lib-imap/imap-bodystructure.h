#ifndef IMAP_BODYSTRUCTURE_H
#define IMAP_BODYSTRUCTURE_H

struct message_part;
struct message_header_line;

/* Write a BODY/BODYSTRUCTURE from given message_part. The message_part->data
   field must be set. part->body_size.virtual_size and .lines are also used
   for writing it. */
void imap_bodystructure_write(const struct message_part *part,
			      string_t *dest, bool extended);

/* Parse BODYSTRUCTURE and save the contents to message_part->data for each
   message tree node. If the parts argument points to NULL, the message_part
   tree is created from the BODYSTRUCTURE. Otherwise, existing tree is used.
   Returns 0 if ok, -1 if bodystructure wasn't valid. */
int imap_bodystructure_parse_full(const char *bodystructure, pool_t pool,
			     struct message_part **parts, const char **error_r);

/* Parse BODYSTRUCTURE and save the contents to message_part->data for each
   message tree node. The parts argument must point to an existing message_part
   tree. Returns 0 if ok, -1 if bodystructure wasn't valid. */
int imap_bodystructure_parse(const char *bodystructure, pool_t pool,
			     struct message_part *parts, const char **error_r);

/* Get BODY part from BODYSTRUCTURE and write it to dest.
   Returns 0 if ok, -1 if bodystructure wasn't valid. */
int imap_body_parse_from_bodystructure(const char *bodystructure,
				       string_t *dest, const char **error_r);

#endif
