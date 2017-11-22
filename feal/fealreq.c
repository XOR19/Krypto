/*************************************************************
**         Europäisches Institut für Systemsicherheit        *
**   Praktikum "Kryptographie und Datensicherheitstechnik"   *
**                                                           *
** Versuch 4: Brechen der Blockchiffre FEAL                  *
**                                                           *
**************************************************************
**
** fealreq.c: Kommunikationsmodul zwischen Client und Feal-Dämon
**/

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "feal_privat.h"

#ifndef USE_UDP
#  include <network.h>
#else
#  include <sys/types.h>
#  include <sys/socket.h>
#  include <netdb.h>
#  include <netinet/in.h>
#endif

#include <unistd.h>
#include <signal.h>

#include <network.h> /* nur fuer MakeNetName */

/*#define TRACE*/ /* Trace aller Kommunikation mit dem Server */

#ifdef USE_UDP
static void sig_alarm(int code)
  {
    fprintf(stderr,"\nFATAL-ERROR: No answer from feal daemon.\n\tPlease contact the administration.\n");
    exit(100);
  }
#endif

/*
 * dorequest(fr) : Sendet den FealRequest FR zum Daemon und wartet auf
 *    die Antwort. Alle Felder in FR außer ->username müssen initialisiert
 *    sein. Username wird von dorequest ausgefüllt.
 *    Tritt beid er Kommunikation ein Fehler auf, so wird nach Ausgabe der
 *    Fehlermeldung das Programm per exit() terminiert!
 */

static void dorequest(struct FealRequest *fr)
  {
#ifdef USE_UDP
    static int s = -1;
    static struct sockaddr_in sin;
    struct hostent *he;
#else
    Connection con;
#endif
    int cnt;

#ifdef TRACE
    static const char *cmdtxt[] = { "NewKey","Cipher","Check","GetCount","Max","Vector" };
#endif

    char *un;
    un= MakeNetName(NULL);
    strncpy(fr->username,un,USERNAMELEN-1);
    fr->username[USERNAMELEN-1]=0;

#ifdef TRACE
    printf("Request %s: u=%02x, v=%02x, k1=%02x, k2=%02x, k3=%02x: ",
           cmdtxt[fr->command-1],fr->u,fr->v,fr->k1,fr->k2,fr->k3);
    fflush(stdout);
#endif

#ifndef USE_UDP
    con=ConnectTo(fr->username,FEALDAEMON_NAME);
    if (!con) {
      fprintf(stderr,"FATAL-ERROR: Cannot connect to Feal Daemon: %s\n",NET_ErrorText());
      exit(1);
    }
    cnt = Transmit(con,fr,sizeof(*fr));
    if (cnt!=sizeof(*fr)) {
      fprintf(stderr,"FATAL-ERROR: Send failure to Feal Daemon: %s\n",NET_ErrorText());
      DisConnect(con);
      exit(1);
    }

    cnt = BReceive(con,fr,sizeof(*fr));
    if (cnt!=sizeof(*fr)) {
      fprintf(stderr,"FATAL-ERROR: Receive failure from Feal Daemon: %s\n",NET_ErrorText());
      DisConnect(con);
      exit(1);
    }
    DisConnect(con);
#else
    if (s==-1) {
      if (!(he = gethostbyname(FEALDAEMON_HOST))) {
	fprintf(stderr,"FATAL-ERROR: Can't unknown fealdaemon servr host " FEALDAEMON_HOST ".\n");
	exit(20);
      }
      sin.sin_family      = AF_INET;
      sin.sin_port        = htons(FEALDAEMON_PORT);
      sin.sin_addr.s_addr = *((u_long *) he->h_addr_list[0]);

      if ( (s = socket(AF_INET,SOCK_DGRAM,0)) < 0 ) {
	perror("FATAL-ERROR: Can't create socket:");
	exit(20);
      }
      signal(SIGALRM,sig_alarm);
    }
    if (sendto(s,(char *) fr,sizeof(*fr),0,(struct sockaddr *) &sin, sizeof(sin))<0) {
      perror("FATAL-ERROR: sendto failed");
      exit(20);
    }

    alarm(5);
    cnt=recv(s,(char *) fr,sizeof(*fr),0);
    alarm(0);

    if (cnt<0) {
      perror("FATAL-ERROR: recv failed");
      exit(20);
    }
    if (cnt!=sizeof(*fr)) {
      fprintf(stderr,"FATAL-ERROR: short read in recv\n.");
      exit(20);
    }
#endif

#ifdef TRACE
    printf("Res = %02x\n",fr->res);
#endif
  }


/*
 * Feal_G(k1,k2,k3,x,y) : Durchführen der Funktion G()
 *
 * RETURN-Code: G(k1,k2,k3,x,y)
 */

ubyte Feal_G(ubyte k1, ubyte k2, ubyte k3, ubyte x, ubyte y)
  {
    x = (x^k1) & 255;
    y = (y^k2) & 255;

    x = (x + y + 1) & 255;
    x = (x << 2) | (x >> 6);

    return (x^k3) & 255;
  }


/*
 * Feal_GS(x,y,ofl) : Berechnet G(x,y,secret_k1,secret_k2,secret_k3). Die
 *    Berechnung wird im Feal-Daemon durchgeführt. OFL wird gesetzt,
 *    wenn der Daemon einen Schlüsselüberlauf meldet.
 *
 * RETURN-CodeL: G'(xmy)
 */

ubyte Feal_GS(ubyte x, ubyte y, int *ofl)
  {
    struct FealRequest fr;

    fr.u = x;
    fr.v = y;
    fr.command = FEALCMD_CIPHER;
    dorequest(&fr);
    *ofl = (fr.res == FEAL_KEYOVERFLOW);
    return fr.res;
  }

/*
 * Feal_CheckKey(k1,k2,k3) : Läßt die Schlüssel vom Daemon auf Korrektheit überprüfem
 *
 * RETURN-Code: Boolean, 1 wenn Schlüssel OK
 */

int Feal_CheckKey(ubyte k1, ubyte k2, ubyte k3)
  {
    struct FealRequest fr;

    fr.k1 = k1;
    fr.k2 = k2;
    fr.k3 = k3;
    fr.command = FEALCMD_CHECK;
    dorequest(&fr);

    return fr.res!=0;
  }


/*
 * Feal_NewKey(): Fordert beim Daemon einen neuen Satz Schlüssel an
 */

void Feal_NewKey(void)
  {
    struct FealRequest fr;

    fr.command = FEALCMD_NEWKEY;
    dorequest(&fr);
  }


/*
 * Feal_GetCount() : Gibt aktuellen Schlüsselgebrauchszähler zurück
 */

int Feal_GetCount(void)
  {
    struct FealRequest fr;

    fr.command = FEALCMD_GETCOUNT;
    dorequest(&fr);

    return fr.res;
  }


/*
 * Feal_GetMaxCount() : Gibt MAximum für Schlüsselgebrauchszähler zurück.
 */

int Feal_GetMaxCount(void)
  {
    struct FealRequest fr;

    fr.command = FEALCMD_GETMAX;
    dorequest(&fr);

    return fr.res;
  }
