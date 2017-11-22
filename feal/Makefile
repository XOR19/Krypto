#
#         Europäisches Institut für Systemsicherheit
#   Proktikum "Kryptographie und Datensicherheitstechnik"
#
# Versuch 3: Brechen der Blockchiffre FEAL
#
#-------------------------------------------------------------
#

include $(PRAKTROOT)/include/Makefile.Settings

feal:	feal.o	fealreq.o
	$(CC) -o feal feal.o fealreq.o $(LFLAGS)

feal.o:		feal.c		feal.h
fealreq.o:	fealreq.c       feal.h	feal_privat.h


#------------------------------------------------------------------------------

clean:
	-rm -f *.o *~ *% feal

