#include "imap-capability-list.h"
#include "array.h"
#include "str.h"

struct imap_capability_list *
imap_capability_list_create(const char *initial_entries)
{
	/* allocate the pool for the capability list */
	pool_t pool = pool_alloconly_create(MEMPOOL_GROWING"Capability List", 512);
	/* initialize a capability list object */
	struct imap_capability_list *
		capability_list = p_new(pool, struct imap_capability_list, 1);
	capability_list->refcount = 1;
	/* initialize the capability list memory pool */
	capability_list->pool = pool;
	/* initialize the capability list capability array */
	p_array_init(&(capability_list->imap_capabilities), pool, 64);

	/* make sure our initial entries are appended */
	if (initial_entries != NULL)
		imap_capability_list_append_string(capability_list, initial_entries);

	return capability_list;
}

void imap_capability_list_ref(struct imap_capability_list *capability_list)
{
	i_assert(capability_list->refcount > 0);

	capability_list->refcount++;
}

void imap_capability_list_unref(struct imap_capability_list **_capability_list)
{
        struct imap_capability_list *capability_list = *_capability_list;

	*_capability_list = NULL;
	i_assert(capability_list->refcount > 0);

	if (--capability_list->refcount > 0)
		return;

	pool_unref(&capability_list->pool);
}

void imap_capability_list_add(struct imap_capability_list *capability_list,
			      const char *name,
			      enum imap_capability_visibility visibility)
{
	/* make sure it isn't already in the list */
	i_assert(imap_capability_list_find(capability_list, name) == NULL);

	struct imap_capability capability;
	/* initialize the capability object */
	capability.name = p_strdup(capability_list->pool, name);
	capability.visibility = visibility;

	/* append new capability object to array */
	array_push_back(&capability_list->imap_capabilities, &capability);
}

void imap_capability_list_remove(struct imap_capability_list *capability_list,
				 const char *name)
{
	/* iterate array of capabilities and find our capability */
	unsigned int i, count;
	const struct imap_capability *cap =
		array_get(&capability_list->imap_capabilities, &count);
	for (i = 0; i < count; i++) {
		if (strcasecmp(cap[i].name, name) == 0) {
			array_delete(&capability_list->imap_capabilities, i, 1);
			return;
		}
	}
	i_unreached();
}

void imap_capability_list_append_string(struct imap_capability_list *capability_list,
					const char *name_list)
{
	T_BEGIN {
		/* split the name list by space */
		const char **strings = t_strsplit_spaces(name_list, " ");
		/* iterate each name and append it to list as ALWAYS */
		while (*strings != NULL) {
			imap_capability_list_add(capability_list, *strings,
						 IMAP_CAP_VISIBILITY_ALWAYS);
			strings++;
		}
	} T_END;
}

static int
imap_capability_bsearch(const char *name, const struct imap_capability *cap)
{
	return strcasecmp(name, cap->name);
}

struct imap_capability *
imap_capability_list_find(struct imap_capability_list *capability_list,
			  const char *name)
{
	return array_bsearch(&capability_list->imap_capabilities,
			     name, imap_capability_bsearch);
}

void imap_capability_list_get_capability(struct imap_capability_list *capability_list,
					 string_t *cap_str,
					 enum imap_capability_visibility visibility)
{
	/* iterate capability list and append each capability if conditions met */
	const struct imap_capability *capp;
	array_foreach(&capability_list->imap_capabilities, capp) {
		/* local visibility variable will get filled with all the
		   visibility flags that matched the current conditions --
		   then at the end if FLAG_REQUIRE_ALL is present the local
		   visibility variable is compared against the capability
		   flags to check for a perfect match */
		if (capp->visibility) {
			/* grab the visibility of the current cap into a tmp variable */
			enum imap_capability_visibility tmp_visibility = capp->visibility;
			/* strip off the REQUIRE_ALL and any visibility flags that don't match */
			tmp_visibility &= (visibility & ~IMAP_CAP_VISIBILITY_FLAG_REQUIRE_ALL);

			bool add = FALSE;
			/* now check if IMAP_CAP_VISIBILITY_FLAG_REQUIRE_ALL is present */
			if ((capp->visibility & IMAP_CAP_VISIBILITY_FLAG_REQUIRE_ALL) != 0) {
				/* did we match all? */
				if ((capp->visibility & ~IMAP_CAP_VISIBILITY_FLAG_REQUIRE_ALL) == tmp_visibility)
					add = TRUE;
			/* no IMAP_CAP_VISIBILITY_FLAG_REQUIRE_ALL - did we match any visibility flags? */
			} else if (tmp_visibility > 0)
				add = TRUE;

			/* should we add this entry? */
			if (add) {
				if (str_len(cap_str) != 0)
					str_append_c(cap_str, ' ');
				str_append(cap_str, capp->name);
			}
		}
	}
}
