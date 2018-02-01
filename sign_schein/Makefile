#
#         Europäisches Institut für Systemsicherheit
#   Proktikum "Kryptographie und Datensicherheitstechnik"
#
# Versuch 7: El-Gamal-Signatur
#

include $(PRAKTROOT)/include/Makefile.Settings

SRC	= signsupport.c getreport.c
VHEADER = sign.h
OBJ	= $(SRC:%.c=%.o)
CFLAGS  += -g
LFLAGS  += -lgmp

BINS	= getreport

all:	$(BINS)

getreport:	getreport.o 	signsupport.o
	$(CC) -o getreport getreport.o signsupport.o $(LFLAGS)

signsupport.o:	signsupport.c	sign.h
getreport.o:	getreport.c	sign.h

#------------------------------------------------------------------------------

clean:
	-rm -f *.o *~ *% $(BINS)
