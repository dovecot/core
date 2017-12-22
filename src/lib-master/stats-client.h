#ifndef STATS_CLIENT_H
#define STATS_CLIENT_H

struct stats_client *
stats_client_init(const char *path, bool silent_notfound_errors);
void stats_client_deinit(struct stats_client **client);

#endif
