/*************************************************************
 **         Europäisches Institut für Systemsicherheit        *
 **   Praktikum "Kryptographie und Datensicherheitstechnik"   *
 **                                                           *
 ** Versuch 4: Brechen der Blockchiffre FEAL                  *
 **                                                           *
 **************************************************************
 **
 ** feal.h Headerfile für den Feal-Versuch
 **/

#include <stdio.h>
#include <stdlib.h>

#include "feal.h"


static ubyte calc_f(ubyte u, ubyte v) {
	int overflow;
	ubyte r;

	r = Feal_GS(u, v, &overflow);
	if (overflow) {
		fprintf(stderr, "FEHLER: Schlüssel-Überlauf, u=%02x, v=%02x\n", u, v);
		exit(20);
	}

	return r;
}

static ubyte ror2(ubyte b) {
	return (b << 6) | (b >> 2);
}

static ubyte rol2(ubyte b) {
	return (b << 2) | (b >> 6);
}

static int known_plaintext_attack_soft(int* pairs) {
	int i;
	int l;
	int m;
	int j;
	for (i = 0; i < 0x100; i++) {
		for(l=0; l<0x80; l++){
			for(m=0; m<0x80; m++){
				int k = i<<16 | l<<8 | m;
				for (j = 0; j < 4; j++) {
					int xored = pairs[j] ^ k;
					if ((((xored & 0xFF) + ((xored >> 8) & 0xFF) + 1) & 0xFF)
							!= ((xored >> 16) & 0xFF))
						goto fail;
				}
				return k;
				fail: ;
			}
		}
	}
	// should not reach
	return -1;
}

static int make_pair(ubyte u, ubyte v){
	return u | v<<8 | ror2(calc_f(u, v))<<16;
}

/* --------------------------------------------------------------------------- */

int main(int argc, char **argv) {
	setUserName("cr4ck1411");

	Feal_NewKey();
	int pairs[4];
	pairs[0] = make_pair(0, 0b01010101);
	pairs[1] = make_pair(0b01010101, 0);
	pairs[2] = make_pair(0, 0b10101010);
	pairs[3] = make_pair(0b10101010, 0);
	int key = known_plaintext_attack_soft(pairs);
	ubyte k1 = key&0xFF;
	ubyte k2 = (key>>8)&0xFF;
	ubyte k3 = rol2((key>>16)&0xFF);
	printf("Lösung: $%02x $%02x $%02x: %s\n", k1, k2, k3,
						Feal_CheckKey(k1, k2, k3) ? "OK!" : "falsch");

	return 0;
}

