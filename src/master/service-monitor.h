#ifndef SERVICE_MONITOR_H
#define SERVICE_MONITOR_H

/* Start listening and monitoring services. */
void services_monitor_start(struct service_list *service_list);

/* Stop services. */
void services_monitor_stop(struct service_list *service_list, bool wait);

/* Call after SIGCHLD has been detected */
void services_monitor_reap_children(void);

void service_monitor_stop(struct service *service);
/* Stop reading the service's status fd. The fd is also closed, except for the
   anvil service, whose status fd is globally shared with the next service
   list and closed only by service_anvil_global_deinit(). */
void service_monitor_close_status_fd(struct service *service);
void service_monitor_stop_close(struct service *service);
void service_monitor_listen_start(struct service *service);
void service_monitor_listen_stop(struct service *service);

#endif
