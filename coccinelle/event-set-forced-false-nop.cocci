@@
expression event;
expression cond;
@@

- if (cond) {
- 	event_set_forced_debug(event,
(
- TRUE
|
- cond
)
- );
- }
+ event_set_forced_debug(event, cond);
