# Linux configuration
#
#AR = ar
#RANLIB = ranlib
#
#CFLAGS  = -DDEBUG -Wall -I../tcp -I../ip -O0
#LDFLAGS = -L../ip -L../tcp -ltcp -lip -lcn
#
# Easiest thing to do is not to change this file every
# time when working on Linux, but to simply create a
# symbolic link from 'aal' to 'ar' (touch already exists)

AR = aal
RANLIB = touch

CFLAGS  = -DDEBUG -Wall -I/usr/local/include/cn -I../../../tcp -I../../../ip -O0
LDFLAGS = -L../ip -L../tcp -L/usr/local/lib -ltcp -lip -lcn

# why do we have to keep updating the Makefile when the test suite changes???
all: telnet.o
	$(CC) $(CFLAGS) -o telnet telnet.o $(LDFLAGS)

#	rm -f *.o

clean:
	rm -f *.o a.out *.bak core errs
	rm -f ../build/*
