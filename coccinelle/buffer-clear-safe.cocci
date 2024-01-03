@@
expression E;
@@

-safe_memset(buffer_get_modifiable_data(E, NULL), 0, E->used);
-buffer_set_used_size(E, 0);
+buffer_clear_safe(E);
