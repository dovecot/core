#ifndef SERVICE_MONITOR_H
#define SERVICE_MONITOR_H

/* Start listening and monitoring services. */
void services_monitor_start(struct service_list *service_list);

/* Stop services. */
void services_monitor_stop(struct service_list *service_list);

/* Call after SIGCHLD has been detected */
void services_monitor_reap_children(void);

void service_monitor_stop(struct service *service);
void service_monitor_listen_start(struct service *service);
void service_monitor_listen_stop(struct service *service);

#endif
