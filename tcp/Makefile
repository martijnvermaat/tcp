# Linux configuration
#
#AR = ar
#RANLIB = ranlib
#
#CFLAGS  = -DDEBUG -Wall -I../ip -O0
#LDFLAGS = -L../ip/ -lip -lcn
#
# Easiest thing to do is not to change this file every
# time when working on Linux, but to simply create a
# symbolic link from 'aal' to 'ar' (touch already exists)

AR = aal
RANLIB = touch

CFLAGS  = -DDEBUG -Wall -I/usr/local/include/cn -I../ip -O0
LDFLAGS = -L../ip/ -L/usr/local/lib -lip -lcn
SOURCES = tcp.c
OBJECTS = tcp.o

all: libtcp.a

libtcp.a: $(OBJECTS)
	$(AR) rv libtcp.a $(OBJECTS)
	$(RANLIB) libtcp.a


clean:
	rm -f $(OBJECTS) libtcp.a a.out *.bak core errs


