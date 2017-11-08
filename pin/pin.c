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
#include <string.h>
#include <getopt.h>
#include <linux/limits.h>
#include <math.h>

#include "pin.h"

/*
 * returns x, than probability of pin is 2^(x-16), desto größer x, desto wahrscheinlicher ist der pin
 */
static int likelyhood(uint32_t pin, uint32_t diff){
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

static uint32_t insert(uint32_t max_size, uint32_t size, double* keys, uint32_t* values, double key, uint32_t value){
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
	}else{
		if(index==0 || keys[--index]>=key)
			return size;
	}
	while(index--){
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

static uint32_t generateLikelyPins(uint32_t num_diffs, const uint32_t* diffs, uint32_t num_pins, uint32_t* pins, double* prob){
	uint32_t i;
	uint32_t pin;
	double likely;
	int l;
	uint32_t valid_pins = 0;
	if(num_pins>9000)
		num_pins = 9000;
	double* pin_likelyhood = prob?prob:malloc(sizeof(double)*9000);
	uint32_t* total_space = (uint32_t*)malloc(sizeof(uint32_t)*(num_diffs+1)*2);
	uint32_t* tmp = total_space + num_diffs + 1;
	for(i=0; i<=num_diffs; i++)
		total_space[i] = 0x10000;
	for(pin=0; pin<10000; pin++){
		uint32_t valid = 1;
		tmp[0] = likelyhood(pin, 0);
		if(tmp[0]==-1)
			valid = 0;
		for(i=1; i<=num_diffs; i++){
			tmp[i] = likelyhood(pin, diffs[i]);
			if(tmp[i]==-1)
				valid = 0;
		}
		if(!valid){
			for(i=0; i<=num_diffs; i++){
				if(tmp[i]!=-1)
					total_space[i] -= 1<<tmp[i];
			}
		}
	}
	for(pin=1000; pin<10000; pin++){
		l = likelyhood(pin, 0);
		likely = (1<<l)/(double)total_space[0];
		for(i=0; i<num_diffs; i++){
			l = likelyhood(pin, diffs[i]);
			if(l==-1)
				goto invalid_pin;
			likely += (1<<l)/(double)total_space[i+1];
		}
		likely /= 3;
		valid_pins = insert(num_pins, valid_pins, prob, pins, likely, pin);
		invalid_pin:
		;
	}
	free(total_space);
	if(!prob)
		free(pin_likelyhood);
	return valid_pins;
}

static int attack(uint32_t num_diffs, const uint32_t* diffs, int offline)
{
	uint32_t max_tries = offline?100:try_max();
	if(max_tries>9000)
		max_tries = 9000;
	uint32_t pin[9000]; // maximale anzahl an pins, da 0??? nicht geht
	double prob[9000];
	uint32_t num_pins = generateLikelyPins(num_diffs, diffs, max_tries, pin, prob);
	if(offline){
		uint32_t i=0;
		double sum = 0;
		for(i=0; i<max_tries; i++){
			double p = prob[i];
			sum += p;
			printf("Pin[%d]=%d with probability %f\n", i, pin[i], p);
		}
		printf("Probability: %f\n", sum);
		return num_pins==0?-1:pin[0];
	}else{
		int index = try_pins(pin, num_pins);
		if(index==-1){
			printf("Die PIN wurde nicht gefunden :(\n");
			return -1;
		}
		printf("Die PIN ist: %d\n", pin[index]);
		return pin[index];
	}

}


static void printhelp(const char* cmd) {
	printf("Aufruf: %s [OPTION]...\n", cmd);
	printf("Optionen:\n");
	printf("  -s, --server      Testserver name\n");
	printf("  -i, --uid         Uid send to Testserver\n");
	printf("  -u, --user        user send to Testserver\n");
	printf("  -d, --diff        Add an diff\n");
	printf("  -o                No test server\n");
	printf("  -h, --help        Diese Hilfe ausgeben und beenden\n");
	printf("  -v, --version     Versionsnummer ausgeben und beenden\n");
	printf("\n");

}

static void printshorthelp(const char* cmd) {
	printf("Aufruf: %s [OPTION]...\n", cmd);
	printf("„%s --help“ liefert weitere Informationen.\n", cmd);
}

static void printversion(void) {
	printf("pin 1.0\n");
}

const static struct option long_options[] = {
		{ "server", required_argument, 0, 's' },
		{ "uid", required_argument, 0, 'i' },
		{ "user", required_argument, 0, 'u' },
		{ "diff", required_argument, 0, 'd' },
		{ "version", no_argument, 0, 'v' },
		{ "help", no_argument, 0, 'h' },
		{ 0, 0, 0, 0 } };

int main(int argc, char **argv)
{

	int server_set = 0;
	char server_name[PATH_MAX];
	char username[PATH_MAX] = "cr4ck1411";
	int uid = 666;

	uint32_t num_diffs = 0;
	struct diffs{
		struct diffs* next;
		uint32_t diff;
	}*diffs = 0;

	int opt;
	int option_index;
	while ((opt = getopt_long(argc, argv, "s:i:u:d:ohH?vV", long_options,
			&option_index)) != -1) {

		switch (opt) {
		case 'h':
		case 'H':
		case '?':
			printhelp(argv[0]);
			exit(0);
		case 'v':
		case 'V':
			printversion();
			exit(0);
		case 's':
			server_set = 1;
			strncpy(server_name, optarg, sizeof(server_name));
			break;
		case 'i':
			uid = (int)strtol(optarg, NULL, 10);
			break;
		case 'u':
			strncpy(username, optarg, sizeof(username));
			break;
		case 'd':
			num_diffs++;
			struct diffs* v = (struct diffs*)malloc(sizeof(struct diffs));
			v->next = diffs;
			v->diff = (uint32_t)strtol(optarg, NULL, 10);
			diffs = v;
			break;
		case 'o':
			server_set = 2;
			break;
		}

	}

	if (optind < argc) {
		printf("Too many arguments\n");
		printshorthelp(argv[0]);
		exit(1);
	}

	if(server_set!=2)
		num_diffs += 2;
	int* diff_array = malloc(sizeof(int)*num_diffs);
	int* ptr = diff_array;
	while(diffs){
		*ptr++ = diffs->diff;
		struct diffs* p = diffs->next;
		free(diffs);
		diffs = p;
	}
	if(server_set!=2)
		open_connection(server_set?server_name:0, ptr, ptr+1, username/*MakeNetName(NULL)*/, uid/*getuid()*/);
	attack(num_diffs, diff_array, server_set==2);
	free(diff_array);
	if(server_set!=2)
		close_connection();
	exit(0);
}
