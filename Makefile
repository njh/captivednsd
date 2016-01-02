CC=gcc
PACKAGE=captivednsd
VERSION=0.2
CFLAGS=-g -Wall -DVERSION=$(VERSION)
LDFLAGS=


all: captivednsd

captivednsd: captivednsd.o
	$(CC) $(LDFLAGS) -o captivednsd captivednsd.o

captivednsd.o: captivednsd.c captivednsd.h
	$(CC) $(CFLAGS) -c captivednsd.c

clean:
	rm -f *.o captivednsd
	
dist:
	distdir='$(PACKAGE)-$(VERSION)'; mkdir $$distdir || exit 1; \
	list=`git ls-files`; for file in $$list; do \
		cp -pR $$file $$distdir || exit 1; \
	done; \
	tar -zcf $$distdir.tar.gz $$distdir; \
	rm -fr $$distdir
	
	
.PHONY: all clean dist
