/*************************************************************
 **         Europäisches Institut für Systemsicherheit        *
 **   Proktikum "Kryptographie und Datensicherheitstechnik"   *
 **                                                           *
 ** Versuch 7: El-Gamal-Signatur                              *
 **                                                           *
 **************************************************************
 **
 ** sign.h: Headerfile für den Signatur-Vrsuch
 **/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <praktikum.h>
#include <gmp.h>
#include <network.h>

#define nbits       512            /* Rechenlänge für diesen Versuch */
#define LineLen      80            /* Länge einer String-Zeile in Zeichen */
#define MaxLines     16            /* Maximale Anzahl von String-Zeilen in einer Nachricht */
#define DAEMON_NAME  "SignSch_Daemon" /* Name des Ports des Signatur-Dämons */

/********************************************************************************/
/*         Datentypen für das Laden der öffentlichen und geheimen Daten         */
/********************************************************************************/
typedef struct {      /* personenbezogene Daten, eigentlich ist nur 'x' geheim! */
	mpz_t p;
	mpz_t w;
	mpz_t x;
} SecretData;

typedef struct {      /* Öffentliche Daten einer Person */
	String name;  /* Name des Inhabers */
	mpz_t y;      /* öffentliches Y */
} PublicData;


/********************************************************************************/
/*         Datenstruktur für die Kommunikation mit dem Signatur-Dämon           */
/********************************************************************************/
typedef enum { ReportRequest, ReportResponse, VerifyRequest, VerifyResponse } MsgType;

typedef struct {
	MsgType typ;                  /* Typ der Nachricht */
	char sign_r[STRINGLEN];       /* elektronische Unterschrift der Nachricht */
	char sign_s[STRINGLEN];
	union {
		struct {                    /* zum Dämon: Anforderung der Punkteauskunft: */
			String Name;              /* .... Gruppenname */
		} ReportRequest;
		struct {                    /* vom Dämon: Auskunft über den Punktestand */
			int NumLines;             /* .... Anzahl der gültigen Zeilen */
			String Report[MaxLines];  /* .... der text selbst */
		} ReportResponse;
		struct {                    /* zum Dämon: Prüfe Deine eigene Signatur */
			int NumLines;             /* .... wie bei ReportResponse */
			String Report[MaxLines];
		} VerifyRequest;
		struct {                    /* vom Dämon: Bestätigung der eigenen Unterschrift */
			String Res;
		} VerifyResponse;
	} body;
} Message;


/********************************************************************************/
/*              Prototypes der Funktionen aus signsupport.c                     */
/********************************************************************************/

void  Generate_MDC        ( const Message *msg, mpz_t p, mpz_t mdc);
int   Get_Public_Key      ( const String name, mpz_t y );
int   Get_Private_Key     ( const char *filename, mpz_t p, mpz_t w, mpz_t x );
