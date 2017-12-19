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
#include <gmp.h>

#include "versuch.h"
                        
/*
 * doexp(x,y,z,p) : Berechnet z := x^y mod p
 * 
 * Hinweise: mpz_init(mpz_t a)		Im Speicher wird der Platz für eine Ganzzahl a zur Verfügung gestellt
 * 					und diese wird mit dem Wert 0 initialisiert.
 * 
 * TODO
 */

void doexp(mpz_t x, mpz_t y, mpz_t z, mpz_t p)
{
	if(!mpz_cmp_ui(x, 1) || !mpz_cmp_ui(y, 0)){
		mpz_set_ui(z, 1);
		return;
	}
	if(!mpz_cmp_ui(x, 0)){
		mpz_set_ui(z, 0);
		return;
	}
	if(!mpz_cmp_ui(y, 1)){
		mpz_set(z, x);
		return;
	}
	
	mpz_t r;
	mpz_init_set_ui(r, 1);
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
	mpz_set(z, r);
	mpz_clear(r);
}
