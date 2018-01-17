#
#         Europäisches Institut für Systemsicherheit
#   Proktikum "Kryptographie und Datensicherheitstechnik"
#
# Versuch: BREACH
#
#-------------------------------------------------------------
#

include $(PRAKTROOT)/include/Makefile.Settings

SOURCE	= attack.c
HEADER	= breach.h
OBJ	= $(SOURCE:%.c=%.o)
CFLAGS  += -g

BINS	= attack


all:	$(BINS)

attack:	attack.o
	$(CC) -o attack attack.o $(LFLAGS)

attack.o:	attack.c	breach.h


#------------------------------------------------------------------------------

clean:
	-rm -f *.o *~ *% $(BINS)
