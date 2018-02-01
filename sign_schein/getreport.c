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

static const char *OverrideNetName = "cr4ck1411";



#include "sign.h"
#include <time.h>

static mpz_t p;
static mpz_t w;
static gmp_randstate_t state;

const char*const MSG[] = {
		"Wir haben bestanden :)",
		NULL
};

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
	mpz_t tmp1,tmp2;
	mpz_inits(tmp1,tmp2,NULL);

	mpz_powm(tmp1, y, r, p);
	mpz_powm(tmp2, r, s, p);
	mpz_mul(tmp1, tmp1, tmp2);
	mpz_mod(tmp1, tmp1, p);

	mpz_powm(tmp2, w, mdc, p);

	int eq = mpz_cmp(tmp1, tmp2);

	mpz_clears(tmp1,tmp2,NULL);

	return !eq;
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
	mpz_t tmp1,tmp2,pm1;
	mpz_inits(tmp1,tmp2,pm1,NULL);
	mpz_sub_ui(pm1, p, 1);

	do{
		mpz_urandomm(tmp1, state, pm1);
	}while(!mpz_invert(tmp2, tmp1, pm1));

	mpz_powm(r, w, tmp1, p);

	mpz_mul(tmp1, r, x);
	mpz_mod(tmp1, tmp1, pm1);
	mpz_sub(tmp1, mdc, tmp1);
	mpz_mul(tmp1, tmp1, tmp2);
	mpz_mod(s, tmp1, pm1);

	mpz_clears(tmp1,tmp2,NULL);
}


static void Generate_Bad_Sign(Message *msg){
	static const DES_key key = { 0x7f,0x81,0x5f,0x92,0x1a,0x97,0xaf,0x18 };
	DES_data reg,desout;
	DES_ikey ikey;
	int i,j,len;
	UBYTE *ptr;

	switch (msg->typ) {
		case ReportRequest:
			ptr = (UBYTE *) &msg->body.ReportRequest;
			len = sizeof(msg->body.ReportRequest.Name);
			break;
		case ReportResponse:
		case VerifyRequest:
			ptr = (UBYTE *) &msg->body.ReportResponse.Report;
			len = sizeof(String)*msg->body.ReportResponse.NumLines;
			break;
		case VerifyResponse:
			ptr = (UBYTE *) &msg->body.VerifyResponse.Res;
			len = sizeof(msg->body.VerifyResponse.Res);
			break;
		default :
			fprintf(stderr,"GENERATE_MDC: Illegaler Typ von Nachricht!\n");
			exit(20);
			break;
	}

	if(len<=0)
		return;

	DES_GenKeys( key,0,ikey);
	for (i=0; i<DES_DATA_WIDTH; i++) reg[i]=0;

	len -= DES_DATA_WIDTH;

	/***************   MDC berechnen   ***************/
	while (len>=DES_DATA_WIDTH) {
		DES_Cipher(ikey,reg,desout);
		for (j=0; j<DES_DATA_WIDTH; j++)
			reg[j] = desout[j] ^ *ptr++;
		len -= DES_DATA_WIDTH;
	}

	DES_Cipher(ikey,reg,desout);
	for (j=0; j<DES_DATA_WIDTH; j++)
		*ptr++ = desout[j];

}

int main(int argc, char **argv)
{
	Connection con;
	int cnt,ok;
	Message msg;
	mpz_t x, Daemon_y, mdc, sign_r, sign_s;
	const char *OurName;

	mpz_inits(x, Daemon_y, mdc, sign_r, sign_s, NULL);

	setenv("PRAKTROOT", ".", 0);

	/**************  Laden der öffentlichen und privaten Daten  ***************/
	if (!Get_Private_Key("private_key.data", p, w, x) || !Get_Public_Key(DAEMON_NAME, Daemon_y)) exit(0);
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
	//Generate_MDC(&msg, p, mdc);                     /* MDC generieren ... */
	Generate_Bad_Sign(&msg);          /* ... und Nachricht unterschreiben */
	strcpy(msg.sign_r, "0");
	strcpy(msg.sign_s, "0");

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

	if (!(con=ConnectTo(OurName,DAEMON_NAME))) {
		fprintf(stderr,"Kann keine Verbindung zum Daemon aufbauen: %s\n",NET_ErrorText());
		exit(20);
	}

	msg.typ = VerifyRequest;
	for(cnt=0; cnt<MaxLines && MSG[cnt]; cnt++){
		strcpy(msg.body.VerifyRequest.Report[cnt], MSG[cnt]);
	}
	msg.body.VerifyRequest.NumLines = cnt;
	Generate_Bad_Sign(&msg);          /* ... und Nachricht unterschreiben */
	strcpy(msg.sign_r, "0");
	strcpy(msg.sign_s, "0");

	if (Transmit(con, &msg, sizeof(msg)) != sizeof(msg)) {
		fprintf(stderr,"Fehler beim Senden des 'VerifyRequest': %s\n",NET_ErrorText());
		exit(20);
	}

	if (Receive(con, &msg, sizeof(msg)) != sizeof(msg)) {
		fprintf(stderr,"Fehler beim Empfang des 'VerifyResponse': %s\n",NET_ErrorText());
		exit(20);
	}

	printf("Nachricht vom Dämon:\n");
	printf("\t%s\n", msg.body.VerifyResponse.Res);

	Generate_MDC(&msg, p, mdc);
	mpz_set_str(sign_r, msg.sign_r, 16);
	mpz_set_str(sign_s, msg.sign_s, 16);
	ok=Verify_Sign(mdc, sign_r, sign_s, Daemon_y);
	if (ok) {
		printf("Dämon-Signatur ist ok!\n");
	} else {
		printf("Dämon-Signatur ist FEHLERHAFT!\n");
	}


	mpz_clears(x, Daemon_y, mdc, sign_r, sign_s, NULL);
	return 0;
}


