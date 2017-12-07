/*************************************************************
**         Europäisches Institut für Systemsicherheit        *
**   Praktikum "Kryptographie und Datensicherheitstechnik"   *
**                                                           *
** Versuch 6: Langzahlarithmetik und Diffie-Hellmann         *
**            Key Exchange                                   *
**                                                           *
**************************************************************
**
** exp.c: Implementierung Modulo-Exponentation.
**/

#include <stdio.h>
#include <stdlib.h>
#include <praktikum.h>
#include <longint.h>

#include "versuch.h"

/*
 * doexp(x,y,z,p) : Berechnet z := x^y mod p
 *
 * Hinweise: LModSquare(a,z,p)    z := a^2 mod p
 *           LModMult(a,b,z,p)    z := a*b mod p
 *           LInt2Long(i,z)       z (longnum) := i (integer) (z muß zuvor mit LInitNumber
 *                                initialisiert werden!!)
 *           LGetBit(y,bitpos)    Gibt bit BITPOS der Lanzahl Y zurück.
 *                                Bit 0 ist das niederwertigste Bit.
 */


void doexp(const_longnum_ptr x,const_longnum_ptr y,longnum_ptr z, const_longnum_ptr p)
  {
  	//TODO
  }
