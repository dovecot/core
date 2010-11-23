.SH OPTIONS
Global
.BR doveadm (1)
.IR options :
.TP
.B \-D
Enables verbosity and debug messages.
.TP
.BI \-f\  formatter
Specifies the
.I formatter
for formatting the output.
Supported formatters are:
.RS
.TP
.B flow
prints each line with
.IB key = value
pairs.
.TP
.B pager
prints each
.IR key :\  value
pair on its own line and separates records with form feed character
.RB ( ^L ).
.TP
.B tab
prints a table header followed by tab separated value lines.
.TP
.B table
prints a table header followed by adjusted value lines.
.RE
.TP
.BI \-s\  socket_path
The option\(aqs argument is either an absolute path to a local UNIX domain
socket, or a hostname and port
.RI ( hostname : port ),
in order to connect a remote host via a TCP socket.
.sp
This allows an administrator to execute
.B doveadm mail
commands through the given socket.
.TP
.B \-v
Enables verbosity, including progress counter.
