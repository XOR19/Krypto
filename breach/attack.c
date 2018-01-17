#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>
#include <sys/types.h>

#include "praktikum.h"
#include "network.h"

#include "breach.h"

#define USER_NAME "cr4ck1411"

Connection con;

static void enc(const char *guess, struct Reply *rpl) {
	/* get the encrypted message from the daemon */
	struct Message msg;
	int cnt;
	memset(&msg, 0, sizeof(msg));
	msg.Type = Guess;
	assert(strlen(guess) < sizeof(msg.Guess));
	strncpy(msg.Guess, guess, sizeof(msg.Guess));
	cnt = Transmit(con, &msg, sizeof(msg));
	if(cnt != sizeof(msg)) {
		printf("Failed to transmit message.\n");
		exit(1);
	}
	cnt = Receive(con, rpl, sizeof(struct Reply));
	if(cnt != sizeof(struct Reply)) {
		printf("Failed to get Reply\n");
		exit(1);
	}
}

static void printhexdata(const void*d, int len) {
	const char* c = (const char*)d;
	while (len-- > 0) {
		printf("%02x", *c++);
	}
}

static int attack(void) {
	struct Reply rpl;
	char password[100] = {0};
	char try[12] = "^pw: ";
	int len = 5;
	int pos = 0;
	int l;
	char fc;
	while(1){
		char c;
		if(len<10){
			try[len] = ' ';
			try[len+1] = '^';
		}else{
			try[10] = ' ';
			try[11] = '^';
		}
		enc(try, &rpl);
		l = rpl.Len;
		fc = ' ';
		for(c='a'; c<='z'; c++){
			if(len<10){
				try[len] = c;
			}else{
				try[10] = c;
			}
			enc(try, &rpl);
			//printf("Try: %s %d\n", try, rpl.Len);
			if(rpl.Len<l){
				l = rpl.Len;
				fc = c;
			}else if(rpl.Len==l){
				fc = 0;
			}
		}
		if(fc==0){
			printf("Problems\n");
			return 0;
		}else if(fc==' ')
			break;
		char b[2];
		b[0] = fc;
		b[1] = 0;
		printf("Next: %s %d\n", b, pos);
		if(len<10){
			try[len] = fc;
		}else{
			memmove(try+1, try+2, 8);
			try[9] = fc;
		}
		password[pos] = fc;
		pos++;
		len++;
	}
	enc(password, &rpl);
	//printhexdata(&rpl, sizeof(rpl));
	printf("\n");
	if(rpl.Type == Correct) {
		printf("Password is \"%s\" (%d bytes total message size)\n", password, rpl.Len);
		return 1;
	} else {
		printf("Password \"%s\" len %d wrong (%d bytes total message size)\n", password, pos, rpl.Len);
		return 0;
	}
}

int main(int argc, char *argv[]) {
	/* initiate communication with daemon */
	const char *us = USER_NAME;
	const char *them = "breach"; /* mind the ro */
	if(!(con = ConnectTo((const char *) us, (const char *) them))) {
		printf("Failed to get daemon's attention: %s\n", NET_ErrorText());
		return 0;
	}
	DisConnect(con);
	them = "breach_" USER_NAME;
	us = USER_NAME "_breach";
	if(!(con = ConnectTo((const char *) us, (const char *) them))) {
		printf("Failed to open channel with daemon: %s\n", NET_ErrorText());
		return 0;
	}
	int result = !attack();
	DisConnect(con);
	return result;
}
