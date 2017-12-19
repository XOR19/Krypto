#
#         Europäisches Institut für Systemsicherheit
#   Proktikum "Kryptographie und Datensicherheitstechnik"
#
# Versuch 6: Langzahlarithmetik und Diffie-Hellmann Key Exchange
#
#-------------------------------------------------------------
#

include $(PRAKTROOT)/include/Makefile.Settings

SOURCE	= exp.c tap.c
HEADER	= versuch.h
OBJ	= $(SOURCE:%.c=%.o)
CFLAGS  += -g
LFLAGS  += -lgmp

BINS	= tap


all:	$(BINS)

tap:	tap.o 	exp.o
	$(CC) -o tap tap.o exp.o $(LFLAGS)

tap.o:	tap.c	versuch.h
exp.o:		exp.c		versuch.h


#------------------------------------------------------------------------------

clean:
	-rm -f *.o *~ *% $(BINS)
