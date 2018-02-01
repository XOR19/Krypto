/*************************************************************
 **         Europäisches Institut für Systemsicherheit        *
 **   Proktikum "Kryptographie und Datensicherheitstechnik"   *
 **                                                           *
 ** Versuch 7: El-gamal-Signatur                              *
 **                                                           *
 **************************************************************
 **
 ** getreport.c: Rahmenprogramm für den Signatur-Versuch
 **/


/* 
 * OverrideNetName: Hier den Gruppennamen einsetzen, falls der nicht 
 *                  mit dem Accountnamen uebereinstimmt
 *                  Andernfalls leerer String
 */

static const char *OverrideNetName = "";



#include "sign.h"
#include <time.h>

static mpz_t p;
static mpz_t w;

/*
 * Verify_Sign(mdc,r,s,y) :
 *
 *  überprüft die El-Gamal-Signatur R/S zur MDC. Y ist der öffentliche
 *  Schlüssel des Absenders der Nachricht
 *
 * RETURN-Code: 1, wenn Signatur OK, 0 sonst.
 */
static int Verify_Sign(mpz_t mdc,  mpz_t r, mpz_t s, mpz_t y)
{
	/*>>>>                                               <<<<*
	 *>>>> AUFGABE: Verifizieren einer El-Gamal-Signatur <<<<*
	 *>>>>                                               <<<<*/
}


/*
 * Generate_Sign(mdc,r,s,x) : Erzeugt zu der MDC eine El-Gamal-Signatur 
 *    in R und S. X ist der private Schlüssel
 */

static void Generate_Sign(mpz_t mdc, mpz_t r, mpz_t s, mpz_t x)
{
	/*>>>>                                           <<<<*
	 *>>>> AUFGABE: Erzeugen einer El-Gamal-Signatur <<<<*
	 *>>>>                                           <<<<*/
}


int main(int argc, char **argv)
{
	Connection con;
	int cnt,ok;
	Message msg;
	mpz_t x, Daemon_y, mdc, sign_r, sign_s;
	const char *OurName;

	mpz_init(x);
	mpz_init(Daemon_y);
	mpz_init(mdc);

	/**************  Laden der öffentlichen und privaten Daten  ***************/
	if (!Get_Private_Key(NULL, p, w, x) || !Get_Public_Key(DAEMON_NAME, Daemon_y)) exit(0);
	/********************  Verbindung zum Dämon aufbauen  *********************/
	OurName = MakeNetName(NULL); /* gibt in Wirklichkeit Unix-Gruppenname zurück! */
	if (strlen(OverrideNetName)>0) {
		OurName = OverrideNetName;
	}
	if (!(con=ConnectTo(OurName,DAEMON_NAME))) {
		fprintf(stderr,"Kann keine Verbindung zum Daemon aufbauen: %s\n",NET_ErrorText());
		exit(20);
	}

	/***********  Message vom Typ ReportRequest initialisieren  ***************/
	msg.typ  = ReportRequest;                       /* Typ setzten */
	strcpy(msg.body.ReportRequest.Name,OurName);    /* Gruppennamen eintragen */
	Generate_MDC(&msg, p, mdc);                     /* MDC generieren ... */
	Generate_Sign(mdc, sign_r, sign_s, x);          /* ... und Nachricht unterschreiben */
	strcpy(msg.sign_r, mpz_get_str(NULL, 16, sign_r));
	strcpy(msg.sign_s, mpz_get_str(NULL, 16, sign_s));

	/*************  Machricht abschicken, Antwort einlesen  *******************/
	if (Transmit(con, &msg, sizeof(msg)) != sizeof(msg)) {
		fprintf(stderr,"Fehler beim Senden des 'ReportRequest': %s\n",NET_ErrorText());
		exit(20);
	}

	if (Receive(con, &msg, sizeof(msg)) != sizeof(msg)) {
		fprintf(stderr,"Fehler beim Empfang des 'ReportResponse': %s\n",NET_ErrorText());
		exit(20);
	}

	/******************  Überprüfen der Dämon-Signatur  ***********************/
	printf("Nachricht vom Dämon:\n");
	for (cnt=0; cnt<msg.body.ReportResponse.NumLines; cnt++) {
		printf("\t%s\n",msg.body.ReportResponse.Report[cnt]);
	}

	Generate_MDC(&msg, p, mdc);
	mpz_set_str(sign_r, msg.sign_r, 16);
	mpz_set_str(sign_s, msg.sign_s, 16);
	ok=Verify_Sign(mdc, sign_r, sign_s, Daemon_y);
	if (ok) {
		printf("Dämon-Signatur ist ok!\n");
	} else {
		printf("Dämon-Signatur ist FEHLERHAFT!\n");
	}

	/*>>>>                                      <<<<*
	 *>>>> AUFGABE: Fälschen der Dämon-Signatur <<<<*
	 *>>>>                                      <<<<*/
	mpz_clears(x, Daemon_y, mdc, sign_r, sign_s, NULL);
	return 0;
}


