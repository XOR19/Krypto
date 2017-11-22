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

static ubyte rotr(ubyte a)
  {
    return ( (a>>2) | (a<<6) ) & 0xff;
  }

static ubyte calc_f(ubyte u, ubyte v)
  {
    int overflow;
    ubyte r;

    r=Feal_GS(u,v,&overflow);
    if (overflow) {
      fprintf(stderr,"FEHLER: Schlüssel-Überlauf, u=%02x, v=%02x\n",u,v);
      exit(20);
    }

    return r;
  }

static void getBit8(ubyte(*Feal_Gs)(ubyte,ubyte), ubyte* keys){
	ubyte t1 = Feal_Gs(keys[0], keys[1]);
	keys[2] = t1 ^ 0b100;
	keys[3] = keys[0] | 0b10000000;
	keys[4] = keys[1] | 0b10000000;
	keys[5] = t1 ^ 0b100;
	keys[6] = keys[0] | 0b10000000;
	keys[7] = keys[1];
	keys[8] = t1 ^ 0b110;
	keys[9] = keys[0];
	keys[10] = keys[1] | 0b10000000;
	keys[11] = t1 ^ 0b110;
}

static void getBit(ubyte(*Feal_Gs)(ubyte,ubyte), ubyte* keys, ubyte bit){
	ubyte mask = 1<<bit;
	ubyte t1 = Feal_Gs(keys[0], keys[1]);
	ubyte t2 = Feal_Gs(keys[0], keys[1]^mask);
	ubyte t3 = Feal_Gs(keys[0]^mask, keys[1]^mask);
	mask = mask<<3 | mask>>5;
	ubyte b14 = t1 & mask;
	ubyte b24 = t2 & mask;
	ubyte b34 = t3 & mask;
	ubyte type;
	if(b14==b24){
		if(b14==b34){
			type = 0b10;
		}else{
			type = 0b00;
		}
	}else{
		if(b14==b34){
			type = 0b01;
		}else{
			type = 0b11;
		}
	}
	if(bit==0)
		type = ~type; // wegen +1
	keys[0] |= (type & 1)<<bit;
	keys[1] |= ((type>>1) & 1)<<bit;
}

/* --------------------------------------------------------------------------- */

int main(int argc, char **argv)
{
	setUserName("c4ack1411");
  ubyte k1,k2,k3;
  Feal_NewKey();
  ubyte keys[12] = {0};
  for(int j=0; j<7; j++){
	  getBit(calc_f, keys, j);
  }
  getBit8(calc_f, keys);
  k1 = keys[0];
  k2 = keys[1];
  k3 = keys[2];
  printf("Lösung: $%02x $%02x $%02x: %s\n",k1,k2,k3, Feal_CheckKey(k1,k2,k3)?"OK!":"falsch" );
  return 0;
}







