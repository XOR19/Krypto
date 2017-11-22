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

/* --------------------------------------------------------------------------- */

int main(int argc, char **argv)
{
  ubyte k1,k2,k3;
  Feal_NewKey();
  /*>>>>                                                      <<<<*/
  /*>>>>  Aufgabe: Bestimmen der geheimen Schlüssel k1,k2,k3  <<<<*/
  /*>>>>                                                      <<<<*/
  printf("Lösung: $%02x $%02x $%02x: %s",k1,k2,k3, Feal_CheckKey(k1,k2,k3)?"OK!":"falsch" );
  return 0;
}







