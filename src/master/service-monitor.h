#ifndef SERVICE_MONITOR_H
#define SERVICE_MONITOR_H

/* Start listening and monitoring services. */
void services_monitor_start(struct service_list *service_list);

/* Stop services. */
void services_monitor_stop(struct service_list *service_list);

/* Call after SIGCHLD has been detected */
void services_monitor_reap_children(struct service_list *service_list);

#endif
