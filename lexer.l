%{
# include "parser.h"
%}

%%

[ \t]               { }
\n                  { return NEWLINE; }
[0]|[1-9][0-9]*     { return NUMBER; }
(allow|deny)        { return ACTION; }
(tcp|udp|icmp|ip)   { return PROTOCOL; }
(([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5]) { return IP; }
any                 { return ANY; }
from                { return FROM; }
to                  { return TO; }
src-port            { return SRCPORT; }
dst-port            { return DSTPORT; }
.                   { yyterminate(); }

%%
