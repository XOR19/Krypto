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

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>

#include "pin.h"

/*
 * returns x, than probability of pin is 2^(x-16), desto größer x, desto wahrscheinlicher ist der pin
 */
int likelyhood(uint32_t pin, uint32_t diff){
	uint32_t i=5;
	int likely = 0;
	uint32_t d;
	while(--i){
		d = (pin+diff)%10;
		pin /= 10;
		diff /= 10;
		if(d<=5) // doppelt so wahrscheinlich wie 6,7,8,9
			likely++;
	}
	if(d==1) // 4 mal so wahrscheinlich als andere, da 0 zu 1 wird
		likely++;
	if(d==0)
		return -1; // erste ziffer kann nicht 0 sein
	return likely;
}

uint32_t insert(uint32_t max_size, uint32_t size, uint32_t* keys, uint32_t* values, uint32_t key, uint32_t value){
	if(size==0){
		if(max_size){
			keys[0] = key;
			values[0] = value;
			return 1;
		}
		return 0;
	}
	uint32_t index = size;
	if(size<max_size){
		size++;
	}else if(keys[index]>=key){
		return size;
	}else{
		--index;
	}
	while(--index){
		if(keys[index]>=key){
			keys[index+1] = key;
			values[index+1] = value;
			return size;
		}
		keys[index+1] = keys[index];
		values[index+1] = values[index];
	}
	keys[0] = key;
	values[0] = value;
	return size;
}

uint32_t generateLikelyPins(uint32_t num_diffs, const uint32_t* diffs, uint32_t num_pins, uint32_t* pins){
	uint32_t i;
	uint32_t j;
	uint32_t pin;
	uint32_t likely;
	int l;
	uint32_t pin_likelyhood[9000];
	uint32_t valid_pins = 0;
	if(num_pins>9000)
		num_pins = 9000;
	for(i=0; i<9000; i++){
		pin = i+1000;
		l = likelyhood(pin, 0);
		if(l==-1)
			continue;
		likely = l;
		for(j=0; j<num_diffs; j++){
			l = likelyhood(pin, diffs[j]);
			if(l==-1)
				goto invalid_pin;
			likely += l;
		}
		valid_pins = insert(num_pins, valid_pins, pin_likelyhood, pins, likely, pin);
		invalid_pin:
		;
	}
	return valid_pins;
}

uint32_t attack(const uint32_t diffs[2])
{
	uint32_t max_tries = try_max();
	if(max_tries>9000)
		max_tries = 9000;
	uint32_t pin[9000]; // maximale anzahl an pins, da 0??? nicht geht
	uint32_t num_pins = generateLikelyPins(2, diffs, max_tries, pin);
	int index = try_pins(pin, num_pins);
	if(index==-1){
		printf("Die PIN wurde nicht gefunden :(\n");
		return -1;
	}
	printf("Die PIN ist: %d\n", pin[index]);
	return pin[index];

}

int main(int argc, char **argv)
{
	int diffs[2];
	open_connection(0, diffs, diffs+1, "cr4ck1411"/*MakeNetName(NULL)*/, 666/*getuid()*/);
	attack(diffs);
	close_connection();
	exit(0);
}
