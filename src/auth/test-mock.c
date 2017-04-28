#include "lib.h"
#include "auth-common.h"

struct auth_penalty *auth_penalty;
time_t process_start_time;
bool worker, worker_restart_request;
void auth_module_load(const char *names ATTR_UNUSED)
{
}
void auth_refresh_proctitle(void) {
}
