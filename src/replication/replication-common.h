#ifndef REPLICATION_COMMON_H
#define REPLICATION_COMMON_H

enum replication_priority {
	/* user is fully replicated, as far as we know */
	REPLICATION_PRIORITY_NONE = 0,
	/* flag changes, expunges, etc. */
	REPLICATION_PRIORITY_LOW,
	/* new emails */
	REPLICATION_PRIORITY_HIGH,
	/* synchronously wait for new emails to be replicated */
	REPLICATION_PRIORITY_SYNC
};

static inline const char *
replicator_priority_to_str(enum replication_priority priority)
{
	switch (priority) {
	case REPLICATION_PRIORITY_NONE:
		return "none";
	case REPLICATION_PRIORITY_LOW:
		return "low";
	case REPLICATION_PRIORITY_HIGH:
		return "high";
	case REPLICATION_PRIORITY_SYNC:
		return "sync";
	}
	i_unreached();
}

static inline int
replication_priority_parse(const char *str,
			   enum replication_priority *priority_r)
{
	if (strcmp(str, "none") == 0)
		*priority_r = REPLICATION_PRIORITY_NONE;
	else if (strcmp(str, "low") == 0)
		*priority_r = REPLICATION_PRIORITY_LOW;
	else if (strcmp(str, "high") == 0)
		*priority_r = REPLICATION_PRIORITY_HIGH;
	else if (strcmp(str, "sync") == 0)
		*priority_r = REPLICATION_PRIORITY_SYNC;
	else
		return -1;
	return 0;
}

#endif
