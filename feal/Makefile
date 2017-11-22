#
#         Europäisches Institut für Systemsicherheit
#   Proktikum "Kryptographie und Datensicherheitstechnik"
#
# Versuch 3: Brechen der Blockchiffre FEAL
#
#-------------------------------------------------------------
#

include $(PRAKTROOT)/include/Makefile.Settings

feal:	feal.o	fealreq.o fealcl.o
	$(CC) -o feal feal.o fealreq.o fealcl.o $(LFLAGS) -ldl -lpthread

feal.o:		feal.c		feal.h
fealreq.o:	fealreq.c       feal.h	feal_privat.h
fealcl.o: fealcl.c

all: feal

#------------------------------------------------------------------------------

clean:
	-rm -f *.o *~ *% feal

