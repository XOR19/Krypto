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
#include <longint.h>

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

static void SetKey(const_longnum_ptr num, CipherKey *ck)
  {
    DES_GenKeys(num->data.b,0,ck->ikey);
    memcpy(ck->iv,num->data.b+DES_DATA_WIDTH,DES_DATA_WIDTH);
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

/* ------------------------------------------------------------------------- */

int main(int argc, char **argv)
{
  Packet pkt;
  Connection con;
  char *name1,*name2;
  int cnt;
  longnum p,w,wa,wb;  /* die globalen Langzahlen in Langzahl-Form */

  /* Langzahlarithmetik initialisieren und Konstanten wandeln */
  LHex2Long(s_p,&p);
  LHex2Long(s_w,&w);
  LHex2Long(s_wa,&wa);
  LHex2Long(s_wb,&wb);


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
   *    direction-Feld angegeben. Das Paket muß explizit weiter transportiert
   *    werden. Außerdem ist zu beachten, daß die Kommunikation nur dann
   *    korrekt funktionier, wenn Alice und Bob immer abwechselnd senden.
   *    Das Unterschlagen eines Paketes führt also zu einem Hänger!
   *
   * Der folgende Programmrahmen zeigt alle abgefangenen Pakete an und
   * leitet sie anschließend korrekt weiter.
   */

  do { /* Schleife über alle Nachrichten ... */
    cnt = Receive(con,&pkt,sizeof(pkt));
    if (cnt==sizeof(pkt)) {

      printf("%s (%2d) ",pkt.direction == DIRECTION_AliceBob ? "Alice->Bob " : "Bob->Alice ",pkt.seqcount);

      if (pkt.tp==PACKETTYPE_Auth) {
	printf("AUTH %s\n",LLong2Hex(&pkt.number,NULL,0,0));
      }
      else {
	printf("DATA "); printstring(pkt.data,pkt.len); printf("\n");
      }
      /* Paket weiterleiten */
      Transmit(con,&pkt,sizeof(pkt));
    }
  }
  while (cnt==sizeof(pkt));
  DisConnect(con);
  return 0;
}

