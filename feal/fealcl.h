/*
 * fealcl.h
 *
 *  Created on: 20.11.2017
 *      Author: Nils
 */

#ifndef FEALCL_H_
#define FEALCL_H_

typedef unsigned char feal_cl_ubyte;
typedef unsigned int feal_cl_size_t;

typedef struct feal_cl_plaintext_pair{
	feal_cl_ubyte u;
	feal_cl_ubyte v;
	feal_cl_ubyte c;
}feal_cl_plaintext_pair;

typedef struct feal_cl_key_pair{
	feal_cl_ubyte k1;
	feal_cl_ubyte k2;
	feal_cl_ubyte k3;
} feal_cl_key_pair;

typedef struct feal_cl_state_* feal_cl_state;


feal_cl_state create_feal_cl(void);
void release_feal_cl(feal_cl_state);
feal_cl_size_t feal_cl_generate_keys(feal_cl_state,feal_cl_size_t,feal_cl_plaintext_pair*,feal_cl_size_t,feal_cl_key_pair*);

#endif /* FEALCL_H_ */
