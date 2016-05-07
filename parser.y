%{
#include <stdio.h>

void yyerror(char *s) { }
%}

/* declare tokens */
%token NUMBER IP
%token ACTION PROTOCOL ANY FROM TO SRCPORT DSTPORT 
%token NEWLINE

%%

/*list: epsilon | rule | rule NEWLINE list;*/

list: rule;
rule: NUMBER ACTION PROTOCOL FROM address TO address src dst;
address: IP | ANY;
src: /* epsilon */ | SRCPORT NUMBER;
dst: /* epsilon */ | DSTPORT NUMBER;

%%

