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
	if(mpz_cmp_ui(x, 1) || mpz_cmp_ui(y, 0)){
		mpz_set_ui(z, 1);
		return;
	}
	if(mpz_cmp_ui(x, 0)){
		mpz_set_ui(z, 0);
		return;
	}
	
	mpz_t r;
	int alloc;
	alloc = x==z || y==z || p==z;
	if(alloc){
		mpz_init_set_ui(r, 1);
	}else{
		r = z;
		mpz_set_ui(r, 1);
	}
	mp_bitcnt_t bit=mpz_sizeinbase(y, 2);

	while(bit--){
		mpz_mul(r, r, r);
		mpz_mod(r, r, p);
		int b = mpz_tstbit(y, bit);
		if(b){
			mpz_mul(r, r, x);
			mpz_mod(r, r, p);
		}
	}
	if(alloc){
		mpz_set(z, r);
		mpz_clear(r);
	}
}
