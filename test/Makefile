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

CFLAGS  = -DDEBUG -Wall -I/usr/local/include/cn -I../tcp -I../ip -O0
LDFLAGS = -L../ip -L../tcp -L/usr/local/lib -ltcp -lip -lcn

all: client server simple

client: client.o
	$(CC) $(CFLAGS) -o client client.o $(LDFLAGS)

server: server.o
	$(CC) $(CFLAGS) -o server server.o $(LDFLAGS)

simple: simple.o
	$(CC) $(CFLAGS) -o simple simple.o $(LDFLAGS)

telnet: telnet.o
	$(CC) $(CFLAGS) -o telnet telnet.o $(LDFLAGS)

clean:
	rm -f *.o server simple client telnet a.out *.bak core errs
