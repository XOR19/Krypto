#
#         Europäisches Institut für Systemsicherheit
#   Proktikum "Kryptographie und Datensicherheitstechnik"
#
# Versuch 6: Langzahlarithmetik und Diffie-Hellmann Key Exchange
#
#-------------------------------------------------------------
#

include $(PRAKTROOT)/include/Makefile.Settings

SOURCE	= exp.c exptest.c alicebob.c
HEADER	= versuch.h
OBJ	= $(SOURCE:%.c=%.o)
CFLAGS  += -g
LFLAGS  += -lgmp

BINS	= exptest alicebob


all:	$(BINS)

exptest:	exptest.o 	exp.o
	$(CC) -o exptest exptest.o exp.o $(LFLAGS)

alicebob:	alicebob.o	exp.o
	$(CC) -o alicebob alicebob.o exp.o $(LFLAGS)

exptest.o:	exptest.c	versuch.h
exp.o:		exp.c		versuch.h
alicebob.o:	alicebob.c	versuch.h
abdaemon.o:	abdaemon.c	versuch.h


#------------------------------------------------------------------------------

clean:
	-rm -f *.o *~ *% $(BINS)
