
CFLAGS=-Wall -g -O1

SRCS=$(wildcard *.c)

OBJECTS=$(SRCS:.c=.o)

all: captivednsd

captivednsd: $(OBJECTS) captivednsd.h Makefile
	gcc -o captivednsd $(OBJECTS)

.c.o: $(SRCS) Makefile
	gcc $(CFLAGS) -c $<

clean:
	rm -f captivednsd *.o *~


install: all
	install  captivednsd /usr/local/sbin/
