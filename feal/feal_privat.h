/*************************************************************
**         Europäisches Institut für Systemsicherheit        *
**   Praktikum "Kryptographie und Datensicherheitstechnik"   *
**                                                           *
** Versuch 4: Brechen der Blockchiffre FEAL                  *
**                                                           *
**************************************************************
**              NUR FÜR DIE PRAKTIKUMSLEITUNG                *
**************************************************************
**
** feal_privat.h Headerfile für Kommunikation mit dem Feal-Dämon
**/

#include "feal.h"

#define USE_UDP  /* wenn gesetzt: Kommunikation erfolgt nicht über EISS-network-Playfield
		  * sondern direkt über UDP */

#define USERNAMELEN       80
#define FEAL_KEYOVERFLOW  65535  /* Wert von RES bei Schlüsselüberlauf */


struct FealRequest {
    char username[USERNAMELEN];
    int command;
    uword res;                     /* Ergebnis der diversen Operationen */
    ubyte u,v;                     /* Verschlüsseln von U und V */
    ubyte k1,k2,k3;                /* key überprüfen */
};

#define FEALCMD_NEWKEY   1   /* neue Schlüssel erzeugen */
#define FEALCMD_CIPHER   2   /* u,v verschlüsseln, Ergebnis in RES */
#define FEALCMD_CHECK    3   /* k1,k2,k3 überprüfen, Erbenis in RES */
#define FEALCMD_GETCOUNT 4   /* Aktuellen Durchlaufzähler holen */
#define FEALCMD_GETMAX   5   /* Maximal-Wert für Durchlaufzähler holen */

#ifndef USE_UDP
#  define FEALDAEMON_NAME "Feal_Daemon"
#else
#  define FEALDAEMON_PORT 6451
#  define FEALDAEMON_HOST "poincare.ira.uka.de"
#endif
