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


void doexp(const mpz_t x,const mpz_t y,mpz_t z, const mpz_t p)
  {
	mpz_set_ui(z, 1);
	mp_bitcnt_t bit=2048;

	while(bit--){
		mpz_mul(z, z, z);
		mpz_mod(z, z, p);
		int b = mpz_tstbit(y, bit);
		if(b){
			mpz_mul(z, z, x);
			mpz_mod(z, z, p);
		}
	}
  }
