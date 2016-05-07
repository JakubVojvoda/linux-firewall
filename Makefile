#
# Simple netfilter firewall for Linux
# by Jakub Vojvoda [vojvoda@swdeveloper.sk]
# 2015
#

PDSCLI = pdscli
CLIFILES = lexer.c parser.c $(PDSCLI).c

PDSFW = pdsfw
obj-m += pdsfw.o

all: $(PDSCLI) $(PDSFW)

parser.c parser.h: parser.y
	bison -d -o parser.c parser.y

lexer.c: lexer.l
	flex -o lexer.c lexer.l

$(PDSCLI): $(CLIFILES)
	gcc -o $(PDSCLI) $(CLIFILES) -lfl

$(PDSFW):
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	rm -f $(PDSCLI) lexer.c parser.c parser.h *~
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean