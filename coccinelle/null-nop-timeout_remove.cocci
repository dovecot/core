@@
expression E;
@@

- if (E != NULL) {
- 	timeout_remove(&E);
- }
+ timeout_remove(&E);
