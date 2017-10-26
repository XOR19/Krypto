include $(PRAKTROOT)/include/Makefile.Settings

SRC	= vigenere.c vigenere-attacke.c
OBJ	= $(SRC:%.c=%.o)
CFLAGS  = $(CFLAGS_DEBUG)
override CFLAGS += -std=c99

BINS	= vigenere vigenere-attacke

vigenere:	vigenere.o
	$(CC) -o $@ $@.o $(LFLAGS)

vigenere-attacke:	vigenere-attacke.o
	$(CC) -o $@ $@.o $(LFLAGS)

all:	$(BINS)

#------------------------------------------------------------------------------

clean:
	-rm -f *.o *~ *% $(BINS)
