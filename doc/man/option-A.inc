.TP
.B \-A
If the
.B \-A
option is present, the
.I command
will be performed for all users.
Using this option in combination with system users from
.B userdb { driver = passwd }
is not recommended, because it contains also users with a lower UID than
the one configured with the
.I first_valid_uid
setting.
.sp
When the sql userdb module is used make sure that the
.I iterate_query
setting in the
.I @sysconfdir@/dovecot/dovecot\-sql.conf.ext
matches your database layout.
Otherwise
.BR doveadm (1)
will be unable to iterate over all users.
