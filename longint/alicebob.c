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

#include "versuch.h"

/**********************  Globale Konstanten  ********************/
const char *s_p  = PUBLIC_DATA_p;
const char *s_w  = PUBLIC_DATA_w;
const char *s_wa = PUBLIC_DATA_wa;
const char *s_wb = PUBLIC_DATA_wb;
       

/* ------------------------------------------------------------------------- */

/*
 * SetKey(num,key) : Wandelt die Langzahl NUM in einen Schlüssel, der für die
 *    Funktionen EnCryptStr und DeCryptStr geeignet ist.
 */

static void SetKey(mpz_t num, CipherKey *ck)
  {
	UBYTE* b = mpz_t2Ubyte(num, MPZLEN);
    DES_GenKeys(b,0,ck->ikey);
    memcpy(ck->iv,b+DES_DATA_WIDTH,DES_DATA_WIDTH);
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

static void packet2mpz(mpz_t ret, Packet* pkt){
	// FIXME DON'T KNOW HOW TO CONVERT
}

static void printAndChange(Packet* pkt){
	printf("DATA "); printstring(pkt->data,pkt->len); printf("\n");
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

/* ------------------------------------------------------------------------- */

int main(int argc, char **argv)
{
  Packet pkt;
  Connection con;
  char *name1,*name2;
  int cnt;
  mpz_t p,w,wa,wb;  /* die globalen Langzahlen in Langzahl-Form */
  mpz_t pkt_num,a,b;
  CipherKey key[4]; // Incoming+Outgoing in both directions

  /* Langzahlarithmetik initialisieren und Konstanten wandeln */
  mpz_init_set_str(p, s_p, 16);
  mpz_init_set_str(w, s_w, 16);
  mpz_init_set_str(wa, s_wa, 16);
  mpz_init_set_str(wb, s_wb, 16);
  mpz_init_set_ui(a, 11); // TODO precalculate
  mpz_init_set_ui(b, 13); // TODO precalculate
  mpz_init(pkt_num);

  /*----  Aufbau der Verbindung zum Alice/Bob-Daemon  ----*/
  name1 = MakeNetName("AliceBob");

  if (!(con = ConnectTo(name1,ABDAEMON_PORTNAME))) {
    fprintf(stderr,"ConnectTo(\"%s\",\"%s\") failed: %s\n",name1,ABDAEMON_PORTNAME,NET_ErrorText());
    exit(20);
  }
  DisConnect(con);
  name1 = MakeNetName("abu");
  name2 = MakeNetName("abd");
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
    		printf("!!! INVALID PACKET !!!\n");
    	}else{
		  printf("%s (%2d) ",pkt.direction == DIRECTION_AliceBob ? "Alice->Bob " : "Bob->Alice ",pkt.seqcount);
	
		  if (pkt.tp==PACKETTYPE_Auth) {
			  packet2mpz(pkt_num, &pkt);
			  doexp(pkt_num, pkt.direction == DIRECTION_AliceBob ? a : b, pkt_num, p);
			  SetKey(plt_num, key + pkt.direction);
			  SetKey(plt_num, key + pkt.direction + 2);
		//printf("AUTH %s\n",LLong2Hex(&pkt.number,NULL,0,0));
		  }
		  else {
			  EnCryptStr(key + pkt.direction, pkt.data, pkt.len);
			  printAndChange(&pkt);
			  DeCryptStr(key + pkt.direction + 2, pkt.data, pkt.len);
		  }
    	}
      /* Paket weiterleiten */
      Transmit(con,&pkt,sizeof(pkt));
    }
  }
  while (cnt==sizeof(pkt));
  DisConnect(con);
  mpz_clears(p, w, wa, wb, a, b, pkt_num, NULL);
  return 0;
}

