#ifndef __MAIL_SORT_H
#define __MAIL_SORT_H

#include "mail-storage.h"

/* Maximum size for sort program, 2x for reverse + END */
#define MAX_SORT_PROGRAM_SIZE (2*7 + 1)

enum mail_sort_type {
	MAIL_SORT_ARRIVAL	= 0x0010,
	MAIL_SORT_CC		= 0x0020,
	MAIL_SORT_DATE		= 0x0040,
	MAIL_SORT_FROM		= 0x0080,
	MAIL_SORT_SIZE		= 0x0100,
	MAIL_SORT_SUBJECT	= 0x0200,
	MAIL_SORT_TO		= 0x0400,

	MAIL_SORT_REVERSE	= 0x0001, /* reverse the next type */

	MAIL_SORT_END		= 0x0000 /* ends sort program */
};

struct mail_sort_funcs {
	/* arrival, date */
	time_t (*input_time)(enum mail_sort_type type, unsigned int id,
			     void *context);
	/* size */
	uoff_t (*input_uofft)(enum mail_sort_type type, unsigned int id,
			      void *context);
	/* cc, from, to. Return the mailbox of the first address. */
	const char *(*input_mailbox)(enum mail_sort_type type, unsigned int id,
				     void *context);
	/* subject */
	const char *(*input_str)(enum mail_sort_type type, unsigned int id,
				 void *context);

	/* done parsing this message, free all resources */
	void (*input_reset)(void *context);

	/* result callback */
	void (*output)(unsigned int *data, size_t count, void *context);
};

/* input and output are arrays of sort programs ending with MAIL_SORT_END.
   input specifies the order in which the messages are arriving to sorting.
   It may be just MAIL_SORT_END if the order is random. The better the ordering
   is known, the less memory is used. */
struct mail_sort_context *
mail_sort_init(const enum mail_sort_type *input, enum mail_sort_type *output,
	       struct mail_sort_funcs funcs, void *context);
void mail_sort_deinit(struct mail_sort_context *ctx);

/* id is either UID or sequence number of message, whichever is preferred
   in MailSortFuncs parameters. */
void mail_sort_input(struct mail_sort_context *ctx, unsigned int id);

#endif
