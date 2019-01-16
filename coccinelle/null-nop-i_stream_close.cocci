@@
expression E;
@@

- if (E != NULL) {
- 	i_stream_close(E);
- }
+ i_stream_close(E);
