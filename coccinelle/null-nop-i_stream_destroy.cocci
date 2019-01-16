@@
expression E;
@@

- if (E != NULL) {
- 	i_stream_destroy(&E);
- }
+ i_stream_destroy(&E);
