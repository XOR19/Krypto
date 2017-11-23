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
#include <stdint.h>
#include <time.h>
#include <getopt.h>
#ifdef __WIN32__
#include <windows.h>
#else
#include <linux/limits.h>
#include <unistd.h>
#endif

#include "feal.h"

typedef struct feal_plaintext_pair {
	uint8_t u;
	uint8_t v;
	uint8_t c;
} feal_plaintext_pair;

typedef struct feal_key_pair {
	uint8_t k1;
	uint8_t k2;
	uint8_t k3;
} feal_key_pair;

static uint8_t calc_f(uint8_t u, uint8_t v) {
	int overflow;
	uint8_t r;

	r = Feal_GS(u, v, &overflow);
	if (overflow) {
		fprintf(stderr, "FEHLER: Schlüssel-Überlauf, u=%02x, v=%02x\n", u, v);
		exit(20);
	}

	return r;
}

static void getBit(uint8_t (*Feal_Gs)(uint8_t, uint8_t), feal_key_pair* keys,
		uint8_t bit) {
	uint8_t mask = 1 << bit;
	uint8_t t1 = Feal_Gs(keys->k1, keys->k2);
	uint8_t t2 = Feal_Gs(keys->k1, keys->k2 ^ mask);
	uint8_t t3 = Feal_Gs(keys->k1 ^ mask, keys->k2 ^ mask);
	mask = mask << 3 | mask >> 5;
	uint8_t b14 = t1 & mask;
	uint8_t b24 = t2 & mask;
	uint8_t b34 = t3 & mask;
	uint8_t type;
	if (b14 == b24) {
		if (b14 == b34) {
			type = 0b10;
		} else {
			type = 0b00;
		}
	} else {
		if (b14 == b34) {
			type = 0b01;
		} else {
			type = 0b11;
		}
	}
	if (bit == 0)
		type = ~type; // wegen +1
	keys->k1 |= (type & 1) << bit;
	keys->k2 |= ((type >> 1) & 1) << bit;
}

static uint32_t choosen_plaintext_attack(uint32_t num_keys,
		feal_key_pair* keys) {
	if (num_keys <= 0)
		return 4;
	keys->k1 = 0;
	keys->k2 = 0;
	int j;
	for (j = 0; j < 7; j++) {
		getBit(calc_f, keys, j);
	}
	ubyte t1 = calc_f(keys->k1, keys->k2);
	keys->k3 = t1 ^ 0b100;
	if (num_keys <= 1)
		return 4;
	keys[1].k1 = keys->k1 | 0b10000000;
	keys[1].k2 = keys->k2 | 0b10000000;
	keys[1].k3 = t1 ^ 0b100;
	if (num_keys <= 2)
		return 4;
	keys[2].k1 = keys->k1 | 0b10000000;
	keys[2].k2 = keys->k2;
	keys[2].k3 = t1 ^ 0b110;
	if (num_keys <= 3)
		return 4;
	keys[3].k1 = keys->k1;
	keys[3].k2 = keys->k2 | 0b10000000;
	keys[3].k3 = t1 ^ 0b110;
	return 4;
}

static ubyte ror2(ubyte b) {
	return (b << 6) | (b >> 2);
}

static ubyte rol2(ubyte b) {
	return (b << 2) | (b >> 6);
}

static uint32_t known_plaintext_attack(uint32_t num_pairs,
		feal_plaintext_pair* pairs, uint32_t num_keys,
		feal_key_pair* keys) {
	uint32_t found_keys = 0;
	int i;
	int l;
	int m;
	uint32_t j;
	uint32_t* p = (uint32_t*)malloc(num_pairs * sizeof(uint32_t));
	for(j=0; j<num_pairs; j++){
		p[j] = pairs[j].u | pairs[j].v<<8 | ror2(pairs[j].c)<<16;
	}
	for(l=0; l<0x80; l++){
		for(m=0; m<0x80; m++){
			uint32_t k = l<<8 | m;
			uint32_t xored = p[0] ^ k;
			i = (((xored & 0xFF) + ((xored >> 8) & 0xFF) + 1) ^ (xored >> 16)) & 0xFF;
			k |= i<<16;
			for (j = 1; j < num_pairs; j++) {
				xored = p[j] ^ k;
				if ((((xored & 0xFF) + ((xored >> 8) & 0xFF) + 1) & 0xFF)
						!= ((xored >> 16) & 0xFF))
					goto fail;
			}
			if(found_keys<num_keys){
				keys[found_keys].k1 = m;
				keys[found_keys].k2 = l;
				keys[found_keys].k3 = rol2(i);
			}
			found_keys++;
			fail: ;
		}
	}
	free(p);
	j=found_keys;
	for(i=0; i<found_keys && j<num_keys; i++){
		keys[j].k1 = keys[i].k1 | 0b10000000;
		keys[j].k2 = keys[i].k2 | 0b10000000;
		keys[j].k3 = keys[i].k3;
		j++;
		if(j>=num_keys)
			break;
		keys[j].k1 = keys[i].k1 | 0b10000000;
		keys[j].k2 = keys[i].k2;
		keys[j].k3 = keys[i].k3 ^ 0b00000010;
		j++;
		if(j>=num_keys)
			break;
		keys[j].k1 = keys[i].k1;
		keys[j].k2 = keys[i].k2 | 0b10000000;
		keys[j].k3 = keys[i].k3 ^ 0b00000010;
		j++;
	}
	return found_keys<<2;
}

static feal_key_pair known_plaintext_attack4(feal_plaintext_pair* pairs) {
	int i;
	int l;
	int m;
	uint32_t j;
	uint32_t p[4];
	for(j=0; j<4; j++){
		p[j] = pairs[j].u | pairs[j].v<<8 | ror2(pairs[j].c)<<16;
	}
	for(l=0; l<0x80; l++){
		for(m=0; m<0x80; m++){
			uint32_t k = l<<8 | m;
			uint32_t xored = p[0] ^ k;
			i = (((xored & 0xFF) + ((xored >> 8) & 0xFF) + 1) ^ (xored >> 16)) & 0xFF;
			k |= i<<16;
			for (j = 1; j < 4; j++) {
				xored = p[j] ^ k;
				if ((((xored & 0xFF) + ((xored >> 8) & 0xFF) + 1) & 0xFF)
						!= ((xored >> 16) & 0xFF))
					goto fail;
			}
			feal_key_pair ret = {m, l, rol2(i)};
			return ret;
			fail: ;
		}
	}
	// should not reach here
	feal_key_pair ret = {0, 0, 0};
	return ret;
}

static uint32_t known_plaintext_attack_rand(uint32_t num_pairs,
		uint32_t num_keys, feal_key_pair* keys) {
	feal_plaintext_pair pairs[num_pairs];
	uint32_t i;
	for (i = 0; i < num_pairs; i++) {
		pairs[i].u = rand() & 0xFF;
		pairs[i].v = rand() & 0xFF;
		pairs[i].c = calc_f(pairs[i].u, pairs[i].v);
	}
	return known_plaintext_attack(num_pairs, pairs, num_keys, keys);
}

static void printhelp(const char* cmd) {
	printf("Aufruf: %s [OPTION]...\n", cmd);
	printf("Optionen:\n");
	printf("  -u, --user        user send to Testserver\n");
	printf("  -k                use known plaintext attack with x random pairs\n");
	printf("  -a                use known plaintext attack, offline, expect pairs after options\n");
	printf("  -m                use minimal, (4) choosen plaintext-cyphertex pairs\n");
	printf("  -t                testing\n");
	printf("  -h, --help        Diese Hilfe ausgeben und beenden\n");
	printf("  -v, --version     Versionsnummer ausgeben und beenden\n");
	printf("\n");
}

static void printshorthelp(const char* cmd) {
	printf("Aufruf: %s [OPTION]...\n", cmd);
	printf("„%s --help“ liefert weitere Informationen.\n", cmd);
}

static void printversion(void) {
	printf("feal 1.0\n");
}

const static struct option long_options[] = {
		{ "user", required_argument, 0, 'u' },
		{ "version", no_argument, 0, 'v' },
		{ "help", no_argument, 0, 'h' },
		{ 0, 0, 0, 0 }
};

static void test(void){
	feal_plaintext_pair pairs[4];
	pairs[0].u = 0;
	pairs[0].v = 0b01010101;
	pairs[1].u = 0b01010101;
	pairs[1].v = 0;
	pairs[2].u = 0b10101010;
	pairs[2].v = 0;
	pairs[3].u = 0;
	pairs[3].v = 0b10101010;
	uint32_t i;
	for(i=0; i<0x400000; i++){
		uint8_t k1 = i&0x7F;
		uint8_t k2 = (i>>7)&0x7F;
		uint8_t k3 = (i>>14)&0xFF;
		pairs[0].c = Feal_G(k1, k2, k3, pairs[0].u, pairs[0].v);
		pairs[1].c = Feal_G(k1, k2, k3, pairs[1].u, pairs[1].v);
		pairs[2].c = Feal_G(k1, k2, k3, pairs[2].u, pairs[2].v);
		pairs[3].c = Feal_G(k1, k2, k3, pairs[3].u, pairs[3].v);
		uint32_t keys = known_plaintext_attack(4, pairs, 0, NULL);
		if(keys!=4){
			printf("Bad: $%02x $%02x $%02x #keys: %d\n", k1, k2, k3, keys);
			exit(10);
		}
		if((i&0xFF)==0){
			printf("At: %06x\n", i);
		}
	}
}

/* --------------------------------------------------------------------------- */

// look in feal.c

int _main(int argc, char **argv) {
	srand(time(NULL));
	char username[PATH_MAX] = "cr4ck1411";

	int known = 0;
	int do_test = 0;

	int opt;
	int option_index;
	while ((opt = getopt_long(argc, argv, "mtau:k:hH?vV", long_options,
			&option_index)) != -1) {

		switch (opt) {
		case 'u':
			strncpy(username, optarg, sizeof(username));
			break;
		case 'k':
			known = (int) strtol(optarg, NULL, 10);
			break;
		case 'a':
			known = -1;
			break;
		case 'm':
			known = -2;
			break;
		case 't':
			do_test = 1;
			break;
		case 'h':
		case 'H':
		case '?':
			printhelp(argv[0]);
			exit(0);
		case 'v':
		case 'V':
			printversion();
			exit(0);
		}

	}

	if(do_test){
		test();
	}else if(known>=0 || known==-2){
		if (optind < argc) {
			printf("Too many arguments\n");
			printshorthelp(argv[0]);
			exit(1);
		}
		setUserName(username);
		uint8_t k1, k2, k3;
		Feal_NewKey();

		feal_key_pair key;
		uint32_t valid;
		if(known==-2){
			feal_plaintext_pair pairs[4];
			pairs[0].u = 0;
			pairs[0].v = 0b01010101;
			pairs[1].u = 0b01010101;
			pairs[1].v = 0;
			pairs[2].u = 0b10101010;
			pairs[2].v = 0;
			pairs[3].u = 0;
			pairs[3].v = 0b10101010;
			pairs[0].c = calc_f(pairs[0].u, pairs[0].v);
			pairs[1].c = calc_f(pairs[1].u, pairs[1].v);
			pairs[2].c = calc_f(pairs[2].u, pairs[2].v);
			pairs[3].c = calc_f(pairs[3].u, pairs[3].v);
			key = known_plaintext_attack4(pairs);
			valid = 4;
		}else if(known>0){
			valid = known_plaintext_attack_rand(known, 1, &key);
		}else{
			valid = choosen_plaintext_attack(1, &key);
		}
		k1 = key.k1;
		k2 = key.k2;
		k3 = key.k3;
		if(valid){
			printf("Lösung: $%02x $%02x $%02x: %s\n", k1, k2, k3,
					Feal_CheckKey(k1, k2, k3) ? "OK!" : "falsch");
		}else{
			printf("Keine valide Lösung??");
		}
	}else{
		int rem = argc - optind;
		if(rem%3!=0 || rem==0){
			printf("Not valid pairs\n");
		}
		rem /= 3;
		feal_plaintext_pair pairs[rem];
		int i;
		for(i=0; i<rem; i++){
			pairs[i].u = (uint8_t) strtol(argv[optind++], NULL, 16);
			pairs[i].v = (uint8_t) strtol(argv[optind++], NULL, 16);
			pairs[i].c = (uint8_t) strtol(argv[optind++], NULL, 16);
		}
		feal_key_pair key;
		uint32_t valid = known_plaintext_attack(rem, pairs, 1, &key);
		if(valid){
			printf("Lösung: $%02x $%02x $%02x von %d Keys\n", key.k1, key.k2, key.k3, valid);
		}else{
			printf("Keine valide Lösung");
		}
	}
	return 0;
}

