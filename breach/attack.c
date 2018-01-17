#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>
#include <sys/types.h>

#include "praktikum.h"
#include "network.h"

#include "breach.h"

Connection con;

void enc(const char *guess, struct Reply *rpl) {
	/* get the encrypted message from the daemon */
	struct Message msg;
	int cnt;
	msg.Type = Guess;
	assert(strlen(guess) < sizeof(((struct Message *) 0)->Guess));
	strcpy(msg.Guess, guess);
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

int attack(void) {
	struct Reply rpl;
	enc("wabbajack", &rpl);
	/*>>>>         <<<<*
	 *>>>> AUFGABE <<<<*
	 *>>>>         <<<<*/
	if(rpl.Type == Correct) {
		printf("Password is \"wabbajack\" (%d bytes total message size)\n", rpl.Len);
		return 1;
	} else {
		printf("Password not found\n");
		return 0;
	}
}

int main(int argc, char *argv[]) {
	/* initiate communication with daemon */
	char *us = MakeNetName("");
	char *them = "breach"; /* mind the ro */
	char *tmp;
	if(!(con = ConnectTo((const char *) us, (const char *) them))) {
		printf("Failed to get daemon's attention: %s\n", NET_ErrorText());
		return 0;
	}
	DisConnect(con);
	tmp = us;
	them = concatstrings("breach_", us, NULL);
	us = concatstrings(us, "_breach", NULL);
	free(tmp);
	if(!(con = ConnectTo((const char *) us, (const char *) them))) {
		printf("Failed to open channel with daemon: %s\n", NET_ErrorText());
		return 0;
	}
	free(us);
	free(them);
	int result = !attack();
	DisConnect(con);
	return result;
}
