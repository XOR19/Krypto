#
#         Europäisches Institut für Systemsicherheit
#   Proktikum "Kryptographie und Datensicherheitstechnik"
#
# Versuch 6: Langzahlarithmetik und Diffie-Hellmann Key Exchange
#
#-------------------------------------------------------------
#

include $(PRAKTROOT)/include/Makefile.Settings

SOURCE	= tap.c
HEADER	= versuch.h
OBJ	= $(SOURCE:%.c=%.o)
CFLAGS  += -g
LFLAGS  += -lgmp -lpthread

BINS	= tap

override CFLAGS += -std=gnu99 


all:	$(BINS)

tap:	tap.o
	$(CC) -o tap tap.o $(LFLAGS)

tap.o:	tap.c	versuch.h


#------------------------------------------------------------------------------

clean:
	-rm -f *.o *~ *% $(BINS)
