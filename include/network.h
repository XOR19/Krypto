/***************************************************************************
**                                                                         *
**                 E.I.S.S. ---  Network-Playfield-System                  *
**                                                                         *
****************************************************************************
**                                                                         *
**   NETWORK.H: Deklarationen fuer die Benutzung der CLIENT-Routinen       *
**              aus CLIENT.C                                               *
**                                                                         *
****************************************************************************
**                                                                         *
**    Filename: network.h                                                  *
**     Version: 1.08, 22-Jun-95                                            *
**      Author: Steffen Stempel (SSA)                                      *
** Source-Host: VANILE                                                     *
**    Modifier: ----                                                       *
**     Support: ----                                                       *
**    Machines: SUN, VAX (UCX), IFDEFed                                    *
**       State: release, (SUN,VAX)                                         *
**                                                                         *
****************************************************************************
**
**  Change-History
**  ==============
**
**   0.01  SSA   07-Aug-90  Initial Creation
**   0.02  SSA   09-Aug-90  Anpassung an VAX/VMS mit Wolongon Software
**   0.10  SSA   10-Aug-90  Sourcecode und Kommentare aufgeraeumt,
**                          Headerfiles aufgespalten
**   0.11  SSA   14-Aug-90  Recompilation von 0.10
**   1.00  SSA   21-Aug-90  Release
**   1.01  SSA   29-Aug-90  Prototypes fuer neues PhoneTapSys
**   1.02  SSA   03-Sep-91  VAX/VMS-Version angepasst auf UCX
**   1.03  SSA   04-Sep-91  NEU: BTapReceive udn BReceive zum Empfang
**                               von GENAU N Zeichen
**                          NEU: SERVER_HOST darf mehrere Hosts durch
**                               Komma getrennt enthalten.
**   1.04  SSA   21-Jul-93  Version-SYNC
**   1.05  SSA   16-Aug-93  Version-SYNC
**   1.06  SSA   23-Aug-94  Erweiterung der PortCOnn-Struct um PeerName,
**                          Neue Funktion Peername()
**   1.07  SSA   03-Sep-94  - BReceive und BTapReceive nach Receive und TapReceive umbenannt.
**                          - Altes Receive gelöscht., altes TapReceive heißt nun VTapReceive.
**   1.08  SSA   22-Jun-95  - Fehler beim Melden von EOF behoben
**                          - zwei neue Fehlercodes 
**/

#ifndef NETWORK_H

#  define NETWORK_H

#  include <sys/types.h>

/*****************  Name innerhalb des Netzwerks  *******************/
#define NETNAME_LEN 80
typedef char NetName[NETNAME_LEN]; 

/**************************  Fehlercodes  *****************************/
#define NETERROR_noerror           0
#define NETERROR_NameExists        1    /* FROM-Name einer Connection existiert schon */
#define NETERROR_TableIsFull       2    /* Servertabelle ist voll */
#define NETERROR_PartnerBusy       3    /* TO einer Connection existiert, hat aber schon
                                           eine verbindung */
#define NETERROR_IllegalConnection 4    /* Verbindungsaufbauversuch zu einem unmoeglichen Partner */
#define NETERROR_CantConnectServer 5
#define NETERROR_ServerUnknown     6
#define NETERROR_SystemSetup       7    /* Fehlermeldung von UNIX */
#define NETERROR_WrongReply        8    /* zu kurzes Reply-Packet */
#define NETERROR_PortConnected     9    /* WaitAtPort(0 bei verbundenem Port */
#define NETERROR_PortExists       10    /* OpenPort: Port existiert schon */
#define NETERROR_IllPortConnect   11    /* PortConnect auf nicht vorhandenes Port oder
                                         * auf etwas, was kein Port ist ... */
#define NETERROR_IllegalNetName   12    /* NetName enthaelt unerlaube Zeichen */
#define NETERROR_WrongHeader      13    /* falscher Header bei TAP und IC */
#define NETERROR_ConnectionDisabled 14  /* TAP/IC-Connection darf nicht mehr gelesen
                                         * werden, da falscher Header */
#define NETERROR_CantWriteToTap   15    /* Versuch, auf eine TAP zu schreiben */
#define NETERROR_Disconnected     16    /* Lesen von oder schreiben auf eine beendeten Verbindung */
#define NETERROR_IO               17    /* IO error, also ein ECHTES Problem! */
#define NETERROR_ERRNO            18    /* Check errno */

extern int NET_Error; /* Enthaelt nach einem CLIENT-Aufruf einen der obigen
                       * Fehlercodes */

/************  Connection-Struct der CLIENT-Routinen  ***************/

/*
 * Diese STRUCTs werden von den Routinen in CLIENT.C dynamisch erzeugt und
 * initialisiert. Sie duerfen unter gar keinen Umstaenden veraendert
 * werden.
 */

typedef struct Connection_S {
          unsigned char type;
          unsigned char flags;                 /* z.Z. noch OHNE bedeutung */
          int fd;                       /* der File-Descriptor */
        } *Connection;

typedef struct PortConnection_S {
          struct Connection_S conn;     /* Connection, die z.Z. ueber das Port laeuft,
                                           nur gueltig, wenn CONNF_PortConnected gesetzt */
          unsigned char type;                  
          unsigned char flags;                 /* CONNF_PortConnected --> Verbindung besteht */
          int fd;                       /* Filedescriptor des Ports */
          NetName portname;             /* Portname von OpenPort() */
	  NetName peername;             /* Name des Kommunikationspartners */
        } *PortConnection;

typedef struct TapConnection_S {
          unsigned char type;
          unsigned char flags;                 /* nur CONNF_Blocked */
          int fd;
          int from;                     /* 0,1 je nach dem, von wem das aktuelle
                                           Packet stammt. */
          int cnt;                      /* Laenge des akt, Packets */
        } *TapConnection;

#define CONNF_PortConnected      (1<<0) /* Nur bei PORTS: 'conn' ist gueltig, Verbindung
                                           besteht */
#define CONNF_Blocked            (1<<1) /* TAP/IC: IO verboten, da falschen Header
                                           empfangen */
#define CONNF_EOF                (1<<2) /* EOF auf dieser Verbindung aufgetreten */

/********  Prototypes der oeffentlichen Routinen in CLIENT.C  ************/
Connection     ConnectTo     ( const char *ourname, const char *othersname );
Connection     ConnectToMaxWait     ( const char *ourname, const char *othersname, int timeout);
void           DisConnect    ( Connection conn );
int            Receive       ( Connection conn, void *buffer, int length );
int            Transmit      ( Connection conn, const void *buffer, int length );
int            sock_timeout  ( int fd, int timeout );
PortConnection OpenPort      ( const char *portname );
void           ClosePort     ( PortConnection pconn );
Connection     WaitAtPort    ( PortConnection pconn );
TapConnection  TapConnect    ( const char *name1, const char *name2 );
int            VTapReceive   ( TapConnection tc, void *buffer, int length, int *from );
int            TapReceive    ( TapConnection tc, void *buffer, int length, int *from );
int            TapTransmit   ( TapConnection tc, const void *buffer, int length, int to );
void           TapDisconnect ( TapConnection tc );
TapConnection  InterConnect  ( const char *name1, const char *name2 );
const char *   NET_ErrorText ( void );
char *         MakeNetName   ( const char *name );
const char *   PeerName      ( PortConnection pc );

/***********  Prototypes von Phone() und PhoneTap() ********************/
typedef char (*CryptFuncPtr)(char);

void           Phone            ( Connection con, const char *name1, const char *name2,
			   	  CryptFuncPtr encrypt, CryptFuncPtr decrypt );
void           PhoneTap         ( TapConnection tc, const char *name1, const char *name2,
				  CryptFuncPtr crypt1, CryptFuncPtr crypt2 );

void           PhoneTap_Init    ( const char *name1, const char *name2 );
void           PhoneTap_Display ( int where, int c );
void           PhoneTap_Clear   ( void );
void           PhoneTap_Die     ( void );

#endif

