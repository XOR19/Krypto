CC=gcc
CFLAGS=-O1 -g

OBJECTS=	pin.o clientlib.o
LIB=

pin: ${OBJECTS}
	cc -o pin ${LDFLAGS} ${OBJECTS} ${LIB}
    override CFLAGS += -std=gnu99 

all: pin

clean:
	rm -f ${OBJECTS} core *.core pin

clientlib.o: clientlib.c
	${CC} ${CFLAGS} -w -c clientlib.c

pin.o: pin.h
clientlib.o: pin.h