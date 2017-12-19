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

#include "versuch.h"

#ifndef BYTE_LENGTH
#define BYTE_LENGTH 256
#endif

/**********************  Globale Konstanten  ********************/
const char *s_p  = PUBLIC_DATA_p;
const char *s_w  = PUBLIC_DATA_w;
const char *s_wa = PUBLIC_DATA_wa;
const char *s_wb = PUBLIC_DATA_wb;

static void printstring(const char *s,int len);

/* ------------------------------------------------------------------------- */

/*
 * SetKey(num,key) : Wandelt die Langzahl NUM in einen Schlüssel, der für die
 *    Funktionen EnCryptStr und DeCryptStr geeignet ist.
 */

static void SetKey(mpz_t num, CipherKey *ck)
  {
    UBYTE * b = mpz_t2Ubyte(num, -1);
    printf("KEY ");
    printstring(b, 16);
    printf("\n");
    DES_GenKeys(b,0,ck->ikey);
    memcpy(ck->iv, b+DES_DATA_WIDTH,DES_DATA_WIDTH);
  }


/*
 * EnCryptStr und DeCryptStr ver- bzw. entschlüsseln jeweils einen
 *   String mit dem angegebenen Schlüssel. Man beachte, daß der
 *   Schlüssel (der IV-Teil) dabei verändert wird!
 */

static void EnCryptStr(CipherKey *ck, char *s, int len)
  {
    DES_CFB_Enc(ck->ikey,ck->iv,(UBYTE *) s,len,(UBYTE *) s);
  }

static void DeCryptStr(CipherKey *ck, char *s, int len)
  {
    DES_CFB_Dec(ck->ikey,ck->iv,(UBYTE *) s,len,(UBYTE *) s);
  }

/*
 * printstring(s,len) : Gibt aus S LEN viele Zeichen aus und expandiert dabei
 *   Steuerzeichen, sodaß diese sichtbar werden.
 */
static void printstring(const char *s,int len)
  {
    unsigned char c;

    while (len-->0) {
      if ( (c=(unsigned char) *s++)=='\n') fputs("\\n",stdout);
      else if (c=='\r') fputs("\\r",stdout);
      else if (c=='\t') fputs("\\t",stdout);
      else if (c=='\0') fputs("\\0",stdout);
      else if (c=='\\') fputs("\\\\",stdout);
      else if (c<' ' || c>=127) fprintf(stdout,"\\x%02x",(unsigned char) c);
      else fputc(c,stdout);
    }
  }

static void setPacketString(Packet* pkt, const char* data){
	int len = strlen(data);
	memcpy(pkt->data, data, len);
	pkt->len = len;
}

static void printAndChange(Packet* pkt){
	printf("DATA "); printstring(pkt->data,pkt->len); printf("\n");
	switch(pkt->seqcount){
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
	printf("SENDING "); printstring(pkt->data,pkt->len); printf("\n");
}

static int is_valid_packet(Packet* pkt){
	if(pkt->direction!=DIRECTION_AliceBob && pkt->direction!=DIRECTION_BobAlice)
		return 0;
	if(pkt->tp!=PACKETTYPE_Auth && pkt->tp!=PACKETTYPE_Data)
		return 0;
	if(pkt->tp==PACKETTYPE_Data){
		if(pkt->len<0 || pkt->len>sizeof(pkt->data))
			return 0;
	}
	return 1;
}

static void slow_exp(mpz_t ret, const mpz_t base, const mpz_t value, const mpz_t mod){
	mpz_t r, v;
	mpz_init_set_ui(r, 0);
	mpz_init_set_ui(v, 1);
	while(mpz_cmp(v, value)){
		mpz_mul(v, v, base);
		mpz_mod(v, v, mod);
		mpz_add_ui(r, r, 1);
	}
	mpz_set(ret, r);
	mpz_clear(r);
}

static unsigned long int slow_exp_ui(const mpz_t base, const mpz_t value, const mpz_t mod){
	mpz_t v;
	unsigned long int r = 0;
	mpz_init_set_ui(v, 1);
	while(mpz_cmp(v, value)){
		mpz_mul(v, v, base);
		mpz_mod(v, v, mod);
		r++;
	}
	return r;
}

/* ------------------------------------------------------------------------- */

int main(int argc, char **argv)
{
  Packet pkt;
  Connection con;
  char *name1,*name2;
  int cnt;
  mpz_t p,w,wa,wb;  /* die globalen Langzahlen in Langzahl-Form */
  mpz_t pkt_num,a,b,one;
  CipherKey key[4]; // Incoming+Outgoing in both directions

  /* Langzahlarithmetik initialisieren und Konstanten wandeln */
  mpz_init_set_str(p, s_p, 16);
  mpz_init_set_str(w, s_w, 16);
  mpz_init_set_str(wa, s_wa, 16);
  mpz_init_set_str(wb, s_wb, 16);
  mpz_init_set_ui(a, 11); // a = 11 (mod 32), precalculated
  mpz_init_set_ui(b, 15); // b = 15 (mod 32), precalculated
  mpz_init_set_ui(one, 1);
  mpz_init(pkt_num);

  /*----  Aufbau der Verbindung zum Alice/Bob-Daemon  ----*/
  name1 = "cr4ck1411_AliceBob";

  if (!(con = ConnectTo(name1,ABDAEMON_PORTNAME))) {
    fprintf(stderr,"ConnectTo(\"%s\",\"%s\") failed: %s\n",name1,ABDAEMON_PORTNAME,NET_ErrorText());
    exit(20);
  }
  DisConnect(con);
  name1 = "cr4ck1411_abu";
  name2 = "cr4ck1411_abd";
  if (!(con = ConnectTo(name1,name2))) {
    fprintf(stderr,"ConnectTo(\"%s\",\"%s\") failed: %s\n",name1,name2,NET_ErrorText());
    exit(20);
  }

  /*
   * WICHTIGER HINWEIS: Auf der Netzwerkverbindung CON werden alle Pakete
   *    angeliefert, die Alice und Bob austauschen. Die Paketrichtung ist im
   *    direction-Feld angegeben. Das Paket muÃŸ explizit weiter transportiert
   *    werden. AuÃŸerdem ist zu beachten, daÃŸ die Kommunikation nur dann
   *    korrekt funktionier, wenn Alice und Bob immer abwechselnd senden.
   *    Das Unterschlagen eines Paketes fÃ¼hrt also zu einem HÃ¤nger!
   *
   * Der folgende Programmrahmen zeigt alle abgefangenen Pakete an und
   * leitet sie anschlieÃŸend korrekt weiter.
   */

  do { /* Schleife Ã¼ber alle Nachrichten ... */
    cnt = Receive(con,&pkt,sizeof(pkt));
    if (cnt==sizeof(pkt)) {

    	if(!is_valid_packet(&pkt)){
    		if(pkt.tp==PACKETTYPE_Error){
    			switch(pkt.errorCode){
    			case 1:
    				printf("Der Server hat sein Datafile nicht gefunden\n");
    				break;
    			case 2:
    				printf("Nutzer nicht vorhanden\n");
    				break;
    			default:
    				printf("Error (%d)\n", pkt.errorCode);
    				break;
    			}
    		}else{
    			printf("!!! INVALID PACKET !!!\n");
    		}
    	}else{
		  printf("%s (%2d) ",pkt.direction == DIRECTION_AliceBob ? "Alice->Bob " : "Bob->Alice ",pkt.seqcount);

		  if (pkt.tp==PACKETTYPE_Auth) {
			  // 18171a0225e2aed352413e3ebe172d8f23d234a7edfeca829f0b0b2d9028a22
			  // aa6aef6638ee9bab065d40960687a60f9cab9c946d7391fa0524cc53dddaad0
			  // b2eee7553429ea891c2aa4405704fc0ba2c35bd563e8334aea3397b23791a54
			  // 1 , has even more problems, so let it be
			  if(pkt.number[0]=='1' && pkt.number[1]=='8' && pkt.number[2]=='1'){
				  pkt.number[strlen("18171a0225e2aed352413e3ebe172d8f23d234a7edfeca829f0b0b2d9028a22")] = 0;
			  }else if(pkt.number[0]=='a' && pkt.number[1]=='a' && pkt.number[2]=='6'){
				  pkt.number[strlen("aa6aef6638ee9bab065d40960687a60f9cab9c946d7391fa0524cc53dddaad0")] = 0;
			  }else if(pkt.number[0]=='b' && pkt.number[1]=='2' && pkt.number[2]=='e'){
				  pkt.number[strlen("b2eee7553429ea891c2aa4405704fc0ba2c35bd563e8334aea3397b23791a54")] = 0;
			  }
			  mpz_set_str(pkt_num, (char*)pkt.number, 16);
			  doexp(pkt_num, pkt.direction == DIRECTION_AliceBob ? b : a, pkt_num, p);
			  SetKey(pkt_num, key + pkt.direction);
			  SetKey(pkt_num, key + pkt.direction + 2);
			  printf("AUTH %s\n",pkt.number);
		  }
		  else {
			  DeCryptStr(key + pkt.direction, pkt.data, pkt.len);
			  printAndChange(&pkt);
			  EnCryptStr(key + pkt.direction + 2, pkt.data, pkt.len);
		  }
    	}
    	printf("Send\n");
      /* Paket weiterleiten */
      Transmit(con,&pkt,sizeof(pkt));
    }
  }
  while (cnt==sizeof(pkt));
  DisConnect(con);
  mpz_clears(p, w, wa, wb, a, b, pkt_num, one, NULL);
  return 0;
}

