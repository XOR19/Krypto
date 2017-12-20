/*************************************************************
 **         Europäisches Institut für Systemsicherheit        *
 **   Praktikum "Kryptographie und Datensicherheitstechnik"   *
 **                                                           *
 ** Versuch 6: Langzahlarithmetik und Diffie-Hellmann         *
 **            Key Exchange                                   *
 **                                                           *
 **************************************************************
 **
 ** alicebob.c: Rahmenprogramm für das Abhören der Unterhaltung
 **             zwischen Alice und Bob.
 **/

#include <stdio.h>
#include <stdlib.h>
#include <praktikum.h>
#include <network.h>
#include <gmp.h>
#include <time.h>
#include <sys/types.h>

#include <arpa/inet.h>
#include <netinet/in.h>

#include <sys/socket.h>

#include <errno.h>
#include <netdb.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>

#include "versuch.h"

#ifndef BYTE_LENGTH
#define BYTE_LENGTH 256
#endif

/**********************  Globale Konstanten  ********************/
const char *s_p = PUBLIC_DATA_p;
const char *s_w = PUBLIC_DATA_w;
const char *s_wa = PUBLIC_DATA_wa;
const char *s_wb = PUBLIC_DATA_wb;

/* ------------------------------------------------------------------------- */

/*
 * SetKey(num,key) : Wandelt die Langzahl NUM in einen Schlüssel, der für die
 *    Funktionen EnCryptStr und DeCryptStr geeignet ist.
 */

static void SetKey(mpz_t num, CipherKey *ck) {
	UBYTE * b = mpz_t2Ubyte(num, -1);
	DES_GenKeys(b, 0, ck->ikey);
	memcpy(ck->iv, b + DES_DATA_WIDTH, DES_DATA_WIDTH);
}

/*
 * EnCryptStr und DeCryptStr ver- bzw. entschlüsseln jeweils einen
 *   String mit dem angegebenen Schlüssel. Man beachte, daß der
 *   Schlüssel (der IV-Teil) dabei verändert wird!
 */

static void EnCryptStr(CipherKey *ck, char *s, int len) {
	DES_CFB_Enc(ck->ikey, ck->iv, (UBYTE *) s, len, (UBYTE *) s);
}

static void DeCryptStr(CipherKey *ck, char *s, int len) {
	DES_CFB_Dec(ck->ikey, ck->iv, (UBYTE *) s, len, (UBYTE *) s);
}

/*
 * printstring(s,len) : Gibt aus S LEN viele Zeichen aus und expandiert dabei
 *   Steuerzeichen, sodaß diese sichtbar werden.
 */
static void printstring(const char *s, int len) {
	unsigned char c;

	while (len-- > 0) {
		if ((c = (unsigned char) *s++) == '\n')
			fputs("\\n", stdout);
		else if (c == '\r')
			fputs("\\r", stdout);
		else if (c == '\t')
			fputs("\\t", stdout);
		else if (c == '\0')
			fputs("\\0", stdout);
		else if (c == '\\')
			fputs("\\\\", stdout);
		else if (c < ' ' || c >= 127)
			fprintf(stdout, "\\x%02x", (unsigned char) c);
		else
			fputc(c, stdout);
	}
}

static void setPacketString(Packet* pkt, const char* data) {
	int len = strlen(data);
	memcpy(pkt->data, data, len);
	pkt->len = len;
}

static void printAndChange(Packet* pkt) {
	printf("DATA ");
	printstring(pkt->data, pkt->len);
	printf("\n");
	switch (pkt->seqcount) {
	case 6:
		setPacketString(pkt, "ja");
		break;
	case 8:
	case 12:
		setPacketString(pkt, "nein");
		break;
	default:
		return;
	}
	printf("SENDING ");
	printstring(pkt->data, pkt->len);
	printf("\n");
}

static int is_valid_packet(Packet* pkt) {
	if (pkt->direction != DIRECTION_AliceBob
			&& pkt->direction != DIRECTION_BobAlice)
		return 0;
	if (pkt->tp != PACKETTYPE_Auth && pkt->tp != PACKETTYPE_Data)
		return 0;
	if (pkt->tp == PACKETTYPE_Data) {
		if (pkt->len < 0 || pkt->len > sizeof(pkt->data))
			return 0;
	}
	return 1;
}

static int try_name(const char* name){
	Connection con;
	Packet pkt;
	int len = strlen(name);
	char* name1 = malloc(len*2+15);
	char* name2 = name1+len+10;
	memcpy(name1, name, len);
	memcpy(name2, name, len);
	memcpy(name1+len, "_AliceBob", 10);
	if (!(con = ConnectTo(name1, ABDAEMON_PORTNAME))) {
		return -1;
	}
	DisConnect(con);
	memcpy(name1+len, "_abu", 5);
	memcpy(name2+len, "_abd", 5);
	if (!(con = ConnectTo(name1, name2))) {
		return -1;
	}
	len = Receive(con, &pkt, sizeof(pkt));
	DisConnect(con);
	return len != sizeof(pkt) || pkt.tp==PACKETTYPE_Error ? 0 : 1;
}

static void crashEISS(void){
	int sd;
	struct hostent *h;
	struct sockaddr_in sin;
	char buf[1024];
	h = gethostbyname("poincare.ira.uka.de");
	if (!h)
		return;
	sd = socket(AF_INET, SOCK_STREAM, 0);
	sin.sin_addr.s_addr = *((int *)(h->h_addr));
	sin.sin_port = htons(6452);
	sin.sin_family = AF_INET;
	if (connect(sd, (const struct sockaddr *)&sin, sizeof(sin)) < 0) {
		return;
	}
	memset(buf, 0, sizeof(buf));
	write(sd, buf, sizeof(buf));
	close(sd);
}

static PortConnection forceOpenPort(const char* name){
	PortConnection pc = OpenPort(name);
	if(pc){
		printf("We got the port, no need to force\n");
		return pc;
	}
	if(NET_Error!=NETERROR_CantConnectServer){
		printf("Port %s not free, crash server\n", name);
		crashEISS();
		printf("Server crashed\n");
	}
	while(1){
		pc = OpenPort(name);
		if(pc){
			printf("We got the port\n");
			return pc;
		}
		if(NET_Error!=NETERROR_CantConnectServer){
			printf("Others where faster\n");
			return 0;
		}
	}
}

mpz_t p, w, wa, wb, a, b;

static void writeToPkt(Packet* pkt, const char* str){
	int len  = strlen(str);
	if(len>sizeof(pkt->data))
		len = sizeof(pkt->data);
	pkt->len = len;
	memcpy(pkt->data, str, len);
	memset(pkt->data+len, 0, sizeof(pkt->data)-len);
}

static int transmit(Connection c, CipherKey* keys, Packet* pkt, const char* peer){
	pkt->seqcount++;
	pkt->tp = PACKETTYPE_Data;
	int len = pkt->len;
	int dir = pkt->direction;
	char send[sizeof(pkt->data)];
	memcpy(send, pkt->data, len);
	EnCryptStr(keys+dir, pkt->data, len);
	Transmit(c, pkt, sizeof(*pkt));
	if(Receive(c, pkt, sizeof(*pkt))!=sizeof(*pkt))
		return 3;
	if(pkt->len<0)
		pkt->len=0;
	if(pkt->len>sizeof(*pkt))
		pkt->len=sizeof(*pkt);
	DeCryptStr(keys+dir+2, pkt->data, pkt->len);
	printf("RECIVED <%s> ", peer);
	printstring(pkt->data, pkt->len);
	printf("\n");
	if(pkt->len!=len)
		return 2;
	return memcmp(send, pkt->data, len);
}

static void * handlePeer(void *arg){
	char* peer = (char*)arg;
	char ourName[80];
	char otherName[80];
	int len = strlen(peer);
	memcpy(ourName, peer, len);
	memcpy(otherName, peer, len);
	memcpy(ourName+len, "_abd", 5);
	memcpy(otherName+len, "_abu", 5);
	printf("Connect to %s %s\n", ourName, otherName);
	Connection c = ConnectToMaxWait(ourName, otherName, 5000);
	if(!c){
		printf("Connect to %s %s failed\n", ourName, otherName);
		goto cleanup;
	}
	printf("Connected to %s %s\n", ourName, otherName);
	CipherKey keys[4];
	Packet pkt;
	mpz_t tmp;
	memset(&pkt, 0, sizeof(pkt));
	mpz_init(tmp);
	int t = rand()&31;
	mpz_powm_ui(tmp, wb, t, p);
	SetKey(tmp, &keys[0]);
	mpz_powm_ui(tmp, w, t, p);
	strncpy((char*)pkt.number, mpz_get_str(NULL, 16, tmp), 128);
	pkt.seqcount++;
	pkt.tp = PACKETTYPE_Auth;
	pkt.direction = DIRECTION_AliceBob;
	Transmit(c, &pkt, sizeof(pkt));
	if(Receive(c, &pkt, sizeof(pkt))!=sizeof(pkt)){
		mpz_clear(tmp);
		goto cleanup;
	}
	mpz_set_str(tmp, (char*)pkt.number, 16);
	mpz_powm(tmp, tmp, b, p);
	SetKey(tmp, &keys[2]);
	t = rand()&31;
	mpz_powm_ui(tmp, wa, t, p);
	SetKey(tmp, &keys[1]);
	mpz_powm_ui(tmp, w, t, p);
	strncpy((char*)pkt.number, mpz_get_str(NULL, 16, tmp), 128);
	pkt.seqcount++;
	pkt.tp = PACKETTYPE_Auth;
	pkt.direction = DIRECTION_BobAlice;
	Transmit(c, &pkt, sizeof(pkt));
	if(Receive(c, &pkt, sizeof(pkt))!=sizeof(pkt)){
		mpz_clear(tmp);
		goto cleanup;
	}
	mpz_set_str(tmp, (char*)pkt.number, 16);
	mpz_powm(tmp, tmp, a, p);
	SetKey(tmp, &keys[3]);
	mpz_clear(tmp);

	writeToPkt(&pkt, "Hallo Bob,");
	pkt.direction = DIRECTION_AliceBob;

	if(transmit(c, keys, &pkt, peer))
		goto notice;

	writeToPkt(&pkt, "Hallo Alice, schoen Dich zu sehen!");
	pkt.direction = DIRECTION_BobAlice;

	if(transmit(c, keys, &pkt, peer))
		goto notice;

	sprintf(pkt.data, "Kennst Du die Praktikumsgruppe %s ?", peer);
	writeToPkt(&pkt, pkt.data);
	pkt.direction = DIRECTION_AliceBob;

	if(transmit(c, keys, &pkt, peer))
		goto notice;

	writeToPkt(&pkt, "nein");
	pkt.direction = DIRECTION_BobAlice;

	if(!transmit(c, keys, &pkt, peer)){

		writeToPkt(&pkt, "Schade, dann darf ich nicht darueber reden. Nan sieht sich Bob,");
		pkt.direction = DIRECTION_AliceBob;

		if(transmit(c, keys, &pkt, peer))
			goto notice;

		writeToPkt(&pkt, "Tschuess Alice");
		pkt.direction = DIRECTION_BobAlice;

		if(transmit(c, keys, &pkt, peer))
			goto notice;
		goto cleanup;
	}

	writeToPkt(&pkt, "Du weisst, was die Gruppe braucht, um den Versuch 6 abzuschliessen ?");
	pkt.direction = DIRECTION_AliceBob;

	if(transmit(c, keys, &pkt, peer))
		goto notice;

	writeToPkt(&pkt, "ja");
	pkt.direction = DIRECTION_BobAlice;

	if(!transmit(c, keys, &pkt, peer)){

		writeToPkt(&pkt, "Dann brauch' ich Dir ja nichts mehr zu sagen. Tschues !");
		pkt.direction = DIRECTION_AliceBob;

		if(transmit(c, keys, &pkt, peer))
			goto notice;

		writeToPkt(&pkt, "Tschuess Alice");
		pkt.direction = DIRECTION_BobAlice;

		if(transmit(c, keys, &pkt, peer))
			goto notice;
		goto cleanup;
	}

	writeToPkt(&pkt, "Ganz einfach, sie muessen ein Geheimnis erfahren.");
	pkt.direction = DIRECTION_AliceBob;

	if(transmit(c, keys, &pkt, peer))
		goto notice;

	writeToPkt(&pkt, "Ein Geheimnis ?");
	pkt.direction = DIRECTION_BobAlice;

	if(transmit(c, keys, &pkt, peer))
		goto notice;

	writeToPkt(&pkt, "Ja, ein Passwort. Du kennst es ?");
	pkt.direction = DIRECTION_AliceBob;

	if(transmit(c, keys, &pkt, peer))
		goto notice;

	writeToPkt(&pkt, "Doch, jetzt faellt es mir wieder ein.");
	pkt.direction = DIRECTION_BobAlice;

	if(!transmit(c, keys, &pkt, peer)){

		writeToPkt(&pkt, "Dann ist ja gut! Tschuess, Bob!");
		pkt.direction = DIRECTION_AliceBob;

		if(transmit(c, keys, &pkt, peer))
			goto notice;

		writeToPkt(&pkt, "Tschuess Alice");
		pkt.direction = DIRECTION_BobAlice;

		if(transmit(c, keys, &pkt, peer))
			goto notice;
		goto cleanup;
	}

	writeToPkt(&pkt, "Pass auf, es heisst \"BADC0DED\"!");
	pkt.direction = DIRECTION_AliceBob;

	if(transmit(c, keys, &pkt, peer))
		goto notice;

	writeToPkt(&pkt, "Ahh, jetzt bin ich im Bilde. Danke Alice!");
	pkt.direction = DIRECTION_BobAlice;

	if(transmit(c, keys, &pkt, peer))
		goto notice;

	writeToPkt(&pkt, "verrate es aber nicht weiter! Tschuess Bob!");
	pkt.direction = DIRECTION_AliceBob;

	if(transmit(c, keys, &pkt, peer))
		goto notice;

	writeToPkt(&pkt, "Tschuess Alice!");
	pkt.direction = DIRECTION_BobAlice;

	if(transmit(c, keys, &pkt, peer))
		goto notice;

	goto cleanup;
	notice:
	writeToPkt(&pkt, "ACHTUNG: Da scheint jemand in der Leitung zu sein!");
	pkt.direction = 1-pkt.direction;
	transmit(c, keys, &pkt, peer);
	cleanup:
	printf("DISCONNECT <%s>\n", peer);
	free(peer);
	if(c)
		DisConnect(c);
	return 0;
}

static void addPeerName(const char* peer){
	FILE *fp;
	char temp[80];

	int pl = strlen(peer);

	if((fp = fopen("peers.txt", "r"))) {
		while(fgets(temp, 80, fp)) {
			int len = strlen(temp)-1;
			if(pl==len && !memcmp(temp, peer, pl)) {
				return;
			}
		}

		fclose(fp);
	}

	if(!(fp = fopen("peers.txt", "a"))) {
		return;
	}

	fprintf(fp, "%s\n", peer);

	fclose(fp);

}

static void onPeerConnect(const char* peer){
	int len = strlen(peer);
	if(len<=9 || len>84 || strcmp(peer+len-9, "_AliceBob"))
		return;
	char* peername = malloc(len-8);
	if(!peername)
		exit(20);
	memcpy(peername, peer, len-9);
	peername[len-9] = 0;
	printf("Peer %s connected\n", peername);
	addPeerName(peername);
	pthread_t thread;
	pthread_create(&thread, NULL, handlePeer, peername);
}

int main(int argc, char **argv){
	srand(time(NULL));
	mpz_init_set_str(p, s_p, 16);
	mpz_init_set_str(w, s_w, 16);
	mpz_init_set_str(wa, s_wa, 16);
	mpz_init_set_str(wb, s_wb, 16);
	mpz_init_set_ui(a, 11); // a = 11 (mod 32), precalculated
	mpz_init_set_ui(b, 15); // b = 15 (mod 32), precalculated
	PortConnection pc = forceOpenPort(argc>1?argv[1]:"ABDaemon");
	if(!pc)
		exit(1);
	while(1){
		Connection c = WaitAtPort(pc);
		if(!c)
			break;
		const char* peer = PeerName(pc);
		onPeerConnect(peer);
		DisConnect(c);
	}
	ClosePort(pc);
	mpz_clears(p, w, wa, wb, a, b, NULL);
	return 0;
}


