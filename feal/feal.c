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
#ifdef __WIN32__
#include <windows.h>
#else
#include <unistd.h>
#include <pthread.h>
#endif

#include "feal.h"
#include "fealcl.h"

#ifdef __WIN32__
typedef HANDLE pthread_mutex_t;
#define pthread_mutex_init(MUTEX_PTR,_) ((*(MUTEX_PTR) = CreateMutex(NULL,FALSE,NULL)),0)
#define pthread_mutex_destroy(MUTEX_PTR) (ReleaseMutex(*(MUTEX_PTR)))
#define pthread_mutex_lock(MUTEX_PTR) (WaitForSingleObject(*(MUTEX_PTR),INFINITE))
#define pthread_mutex_unlock(MUTEX_PTR) (ReleaseMutex(*(MUTEX_PTR)))
typedef HANDLE pthread_t;
#define pthread_create(THREAD_PTR,_,FUNC_PTR,ARGS) ((*(THREAD_PTR) = CreateThread(NULL,0,(LPTHREAD_START_ROUTINE) (FUNC_PTR),(ARGS),0,NULL)),0)
#define pthread_join(THREAD,_) (WaitForSingleObject(THREAD,INFINITE))
#endif

static ubyte calc_f(ubyte u, ubyte v) {
	int overflow;
	ubyte r;

	r = Feal_GS(u, v, &overflow);
	if (overflow) {
		fprintf(stderr, "FEHLER: Schlüssel-Überlauf, u=%02x, v=%02x\n", u, v);
		exit(20);
	}

	return r;
}

static void getBit(ubyte (*Feal_Gs)(ubyte, ubyte), feal_cl_key_pair* keys,
		ubyte bit) {
	ubyte mask = 1 << bit;
	ubyte t1 = Feal_Gs(keys->k1, keys->k2);
	ubyte t2 = Feal_Gs(keys->k1, keys->k2 ^ mask);
	ubyte t3 = Feal_Gs(keys->k1 ^ mask, keys->k2 ^ mask);
	mask = mask << 3 | mask >> 5;
	ubyte b14 = t1 & mask;
	ubyte b24 = t2 & mask;
	ubyte b34 = t3 & mask;
	ubyte type;
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

static feal_cl_size_t choosen_plaintext_attack(feal_cl_size_t num_keys,
		feal_cl_key_pair* keys) {
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

typedef struct {
	feal_cl_size_t num_keys;
	feal_cl_size_t max_keys;
	feal_cl_key_pair* keys;
	feal_cl_size_t num_pairs;
	uint32_t* pairs;
	pthread_mutex_t lock;
} thread_global_data;

typedef struct {
	thread_global_data* g;
	uint32_t start;
	uint32_t end;
	pthread_t thread;
} thread_data;

static feal_cl_ubyte ror2(feal_cl_ubyte b) {
	return (b << 6) | (b >> 2);
}

static feal_cl_ubyte rol2(feal_cl_ubyte b) {
	return (b << 2) | (b >> 6);
}

static void *known_plaintext_attack_thread(void *arg) {
	thread_data* data = (thread_data*) arg;
	thread_global_data* g = data->g;
	uint32_t i;
	int j;
	for (i = data->start; i < data->end; i++) {
		for (j = 0; j < g->num_pairs; j++) {
			uint32_t xored = g->pairs[j] ^ i;
			if ((((xored & 0xFF) + ((xored >> 8) & 0xFF) + 1) & 0xFF)
					!= ((xored >> 16) & 0xFF))
				goto fail;
		}
		pthread_mutex_lock(&g->lock);
		j = g->num_keys++;
		pthread_mutex_unlock(&g->lock);
		if (j < g->max_keys) {
			g->keys[j].k1 = i & 0xFF;
			g->keys[j].k2 = (i >> 8) & 0xFF;
			g->keys[j].k3 = rol2((i >> 16) & 0xFF);
		}
		fail: ;
	}
	return 0;
}

static feal_cl_size_t known_plaintext_attack_soft(feal_cl_size_t num_pairs,
		feal_cl_plaintext_pair* pairs, feal_cl_size_t num_keys,
		feal_cl_key_pair* keys) {
#ifdef __WIN32__
	SYSTEM_INFO sysinfo;
	GetSystemInfo(&sysinfo);
	int num_proc = sysinfo.dwNumberOfProcessors;
#else
	int num_proc = sysconf(_SC_NPROCESSORS_ONLN);
#endif
	if (num_proc < 0 || num_proc == 0 || num_proc > 255) {
		num_proc = 1;
	}
	int i;
	thread_global_data g;
	g.num_keys = 0;
	g.max_keys = num_keys;
	g.num_pairs = num_pairs;
	g.keys = keys;
	g.pairs = (uint32_t*) malloc(num_pairs * sizeof(uint32_t));
	for (i = 0; i < num_pairs; i++) {
		g.pairs[i] = (pairs[i].u & 0xFF) | ((pairs[i].v & 0xFF) << 8)
				| ((ror2(pairs[i].c) & 0xFF) << 16);
	}
	pthread_mutex_init(&g.lock, NULL);
	thread_data* thread_datas = (thread_data*) malloc(
			num_proc * sizeof(thread_data));
	uint32_t t = 0;
	uint32_t inc = 0x1000000 / num_proc;
	for (i = 0; i < num_proc; i++) {
		thread_datas[i].g = &g;
		thread_datas[i].start = t;
		t += inc;
		thread_datas[i].end = t;
		pthread_create(&thread_datas[i].thread, NULL,
				known_plaintext_attack_thread, (void* )&thread_datas[i]);
	}
	if (t < 0x1000000) {
		thread_data d = { &g, t, 0x1000000, 0 };
		known_plaintext_attack_thread(&d);
	}
	for (i = 0; i < num_proc; i++) {
		pthread_join(thread_datas[i].thread, NULL);
	}
	pthread_mutex_destroy(&g.lock);
	free(thread_datas);
	return g.num_keys;
}

static feal_cl_size_t known_plaintext_attack(feal_cl_size_t num_pairs,
		feal_cl_plaintext_pair* pairs, feal_cl_size_t num_keys,
		feal_cl_key_pair* keys) {
	feal_cl_state cl_state = create_feal_cl();
	if (cl_state) {
		printf("Using OpenCL\n");
		feal_cl_size_t max_keys = feal_cl_generate_keys(cl_state, num_pairs,
				pairs, num_keys, keys);
		release_feal_cl(cl_state);
		return max_keys;
	} else {
		printf("Using Software\n");
		return known_plaintext_attack_soft(num_pairs, pairs, num_keys, keys);
	}
}

static feal_cl_size_t known_plaintext_attack_rand(feal_cl_size_t num_pairs,
		feal_cl_size_t num_keys, feal_cl_key_pair* keys) {
	feal_cl_plaintext_pair pairs[num_pairs];
	int i;
	for (i = 0; i < num_pairs; i++) {
		pairs[i].u = rand() & 0xFF;
		pairs[i].v = rand() & 0xFF;
		pairs[i].c = calc_f(pairs[i].u, pairs[i].v);
	}
	return known_plaintext_attack(num_pairs, pairs, num_keys, keys);
}

/* --------------------------------------------------------------------------- */

int main(int argc, char **argv) {
	srand(time(NULL));
	setUserName("c4ack1411");
	ubyte k1, k2, k3;
	Feal_NewKey();

	feal_cl_key_pair key;
	known_plaintext_attack_rand(10, 1, &key);
	k1 = key.k1;
	k2 = key.k2;
	k3 = key.k3;
	printf("Lösung: $%02x $%02x $%02x: %s\n", k1, k2, k3,
			Feal_CheckKey(k1, k2, k3) ? "OK!" : "falsch");
	return 0;
}

