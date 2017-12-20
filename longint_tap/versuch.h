/*************************************************************
**         Europäisches Institut für Systemsicherheit        *
**   Praktikum "Kryptographie und Datensicherheitstechnik"   *
**                                                           *
** Versuch 6: Langzahlarithmetik und Diffie-Hellmann         *
**            Key Exchange                                   *
**                                                           *
**************************************************************
**
** versuch.h: headerfile für Moduloexponentation und
**            das Alice/Bob-gespräch
**/

#include <praktikum.h>

typedef enum { DIRECTION_AliceBob,DIRECTION_BobAlice } Direction_Typ;
typedef enum { PACKETTYPE_Auth, PACKETTYPE_Data, PACKETTYPE_Error} Packet_Typ;
typedef char Data_Typ[STRINGLEN];

/*
 * Paket für den Datenaustausch zwischen Alice und Bob
 */
typedef struct {
  Direction_Typ direction;  /* Richtung: Alice-->Bob,  Bob-->Alice */
  int seqcount;             /* laufende Paketnummer */
  Packet_Typ tp;            /* Paket-Typ */
  UBYTE number[MPZLEN]; /* Bei tp==Auth: Authentifikationsdaten in Form einer Langzahl */
  Data_Typ data;            /* Bei tp==Data: Nutzdaten in Form eines chiffrierten Strings */
  int len;                  /*               Anzahl der gültigen Zeichen in DATA */
  int errorCode;            /* Bei tb==Error: Der Fehlercode
                                 1: Der Server hat sein Datafile nicht gefunden
                                 2: Nutzer nicht vorhanden
                             */

} Packet;


/*
 * Datenstruktur, die einen Schlüssel beschreibt
 */
typedef struct {
  DES_ikey ikey;    /* DES Schlüssel in der internen Form */
  DES_data iv;      /* IV für Cipher Feedback Mode (CFB) */
} CipherKey;


/*
 * Öffentlich bekannte Daten von Alice und Bob für den Schlüsselaustausch
 */
#define nbits 256
#define PUBLIC_DATA_p  "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEF7F41E4FF00000800000000FF0DFB61"
#define PUBLIC_DATA_w  "018171A0225E2AED352413E3EBE172D8F23D234A7EDFECA829F0B0B2D9028A22"
#define PUBLIC_DATA_wa "64D97C126532B0A8E778825BE181DA940993849183BB8F98CB84AA5F81348C39"
#define PUBLIC_DATA_wb "0AA6AEF6638EE9BAB065D40960687A60F9CAB9C946D7391FA0524CC53DDDAAD0"


#define ABDAEMON_PORTNAME "ABDaemon"
