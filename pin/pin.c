/*************************************************************
**         Europäisches Institut für Systemsicherheit        *
**   Praktikum "Kryptographie und Datensicherheitstechnik"   *
**                                                           *
** Versuch 3: Brechen von EC-Karten PINs                     *
**                                                           *
**************************************************************
**
** pin.c Headerfile für den PIN-Versuch
**/

#include <stdio.h>
#include <stdlib.h>

#include "pin.h"

int diff1, diff2;


int pin[9000], prob[9000], try[9000];


void attack(void)
{
	int i;
  /*>>>>                                                      <<<<*/
  /*>>>>  Aufgabe: Bestimmen die PIN                          <<<<*/
  /*>>>>                                                      <<<<*/
  printf("Die PIN ist: %d\n", i);

}

int main(void)
{
	open_connection(0, &diff1, &diff2);
	attack();
	close_connection();
	exit(0);
}
