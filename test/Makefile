# Linux configuration
#
#AR = ar
#RANLIB = ranlib
#
#CFLAGS  = -DDEBUG -Wall -I../tcp -I../ip -O0
#LDFLAGS = -L../ip -L../tcp -ltcp -lip -lcn

AR = aal
RANLIB = touch

CFLAGS  = -DDEBUG -Wall -I/usr/local/include/cn -I../tcp -I../ip -O0
LDFLAGS = -L../ip -L../tcp -L/usr/local/lib -ltcp -lip -lcn

all: client server

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
