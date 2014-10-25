.SH OPTIONS
Global
.BR doveadm (1)
.IR options :
.TP
.B \-D
Enables verbosity and debug messages.
.TP
.BI \-o\  setting = value
Overrides the configuration
.I setting
from
.I @pkgsysconfdir@/dovecot.conf
and from the userdb with the given
.IR value .
In order to override multiple settings, the
.B \-o
option may be specified multiple times.
.TP
.B \-v
Enables verbosity, including progress counter.
