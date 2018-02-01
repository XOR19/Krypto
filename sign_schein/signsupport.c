/*************************************************************
 **         Europäisches Institut für Systemsicherheit        *
 **   Proktikum "Kryptographie und Datensicherheitstechnik"   *
 **                                                           *
 ** Versuch 7: El-Gamal-Signatur                              *
 **                                                           *
 **************************************************************
 **
 ** signsupport.c: Laden der Personendaten und Erzeugen des MDC
 **/

#include "sign.h"

#ifndef BYTE_LENGTH
#	define BYTE_LENGTH 256
#endif

/*
 * Generate_MDC( msg, P, mdc ) :
 *
 *   Berechnet die MDC zur Nachricht MSG. Der zu unterschreibende Teil 
 *   von MSG (ist abhängig vom Typ) wird als Byte-Array interpretiert
 *   und darüber der MDC berechnet. P ist der globale El-Gamal-Modulus.
 *
 * ACHTUNG: msg.type muß unbedingt richtig gesetzt sein!
 */

void Generate_MDC( const Message *msg, mpz_t p, mpz_t mdc)
{
	static const DES_key key = { 0x7f,0x81,0x5f,0x92,0x1a,0x97,0xaf,0x18 };
	DES_data reg,desout;
	DES_ikey ikey;
	int i,j,len;
	const UBYTE *ptr;

	switch (msg->typ) {
		case ReportRequest:
			ptr = (const UBYTE *) &msg->body.ReportRequest;
			len = sizeof(msg->body.ReportRequest.Name);
			break;
		case ReportResponse:
			ptr = (const UBYTE *) &msg->body.ReportResponse.Report;
			len = sizeof(String)*msg->body.ReportResponse.NumLines;
			break;
		case VerifyRequest:
			ptr = (const UBYTE *) &msg->body.VerifyRequest.Report;
			len = sizeof(String)*msg->body.VerifyRequest.NumLines;
			break;
		case VerifyResponse:
			ptr = (const UBYTE *) &msg->body.VerifyResponse.Res;
			len = sizeof(msg->body.VerifyResponse.Res);
			break;
		default :
			fprintf(stderr,"GENERATE_MDC: Illegaler Typ von Nachricht!\n");
			exit(20);
			break;
	}

	DES_GenKeys( key,0,ikey);
	for (i=0; i<DES_DATA_WIDTH; i++) reg[i]=0;

	/***************   MDC berechnen   ***************/
	while (len>=DES_DATA_WIDTH) {
		DES_Cipher(ikey,reg,desout);
		for (j=0; j<DES_DATA_WIDTH; j++)
			reg[j] = desout[j] ^ *ptr++;
		len -= DES_DATA_WIDTH;
	}

	if (len>0) { /* LEN ist KEIN Vielfaches von 8 ! */
		DES_Cipher(ikey,reg,desout);
		for (j=0; j<len; j++)
			reg[j] = desout[j] ^ *ptr++;
		for (j=len; j<DES_DATA_WIDTH; j++)
			reg[j] = desout[j];
	}

	/***************  MDC konvertieren  ***************/
	mpz_init_set_ui(mdc, 0);

	for (j = DES_DATA_WIDTH - 1; j >= 0; j--)
	{
		mpz_mul_ui(mdc, mdc, BYTE_LENGTH); //mdc = reg;
		mpz_add_ui(mdc, mdc, reg[j]);
	}

	for (j=0; j<8; j++)
		mpz_powm_ui(mdc, mdc, 2, p);
}



/*
 * Get_Public_Key(name,y) :
 *
 *  Sucht in der systemweiten Tabelle den öffentlichen Schlüssel des
 *  Teilnehmers NAME und speichert ihn in Y.
 *  
 * RETURN-Code: 1 bei Erfolg, 0 sonst.
 */

int Get_Public_Key( const String name, mpz_t y)
{
	FILE *f;
	char *filename;
	const char *root;
	char *line = NULL;
	size_t *bufsize = malloc(sizeof(int));
	*bufsize = 0;
	int found = 0;

	if (!(root=getenv("PRAKTROOT"))) root=getenv("HOME");
	filename=concatstrings(root,"/loesungen/sign_schein/public_keys.data",NULL);
	if (!(f=fopen(filename,"r"))) {
	  filename=concatstrings(root,"/public_keys.data",NULL);
          if (!(f=fopen(filename,"r"))) {
            fprintf(stderr,"GET_PUBLIC_KEY: Kann die Datei %s nicht öffnen: %s\n",filename,strerror(errno));
            exit(20);
          }
	}
	free(filename);

	while (!feof(f) && getline(&line,bufsize,f)>0 && !(found=!(strcmp(line,name))));
	if(found) {
		getline(&line,bufsize,f);
		mpz_set_str(y, line, 16);
		fclose(f);
		return 1;
	} else {
		fprintf(stderr,"GET_PUBLIC_KEY: Benutzer \"%s\" nicht gefunden\n",name);
	}
	fclose(f);
	return 0;
}


/*
 * Get_Private_Key(filename,p,w,x) :
 *
 *  Läd den eigenen geheimen Schlüssel nach X. Die globalen (öffentlichen)
 *  Daten P und W werden ebenfalls aus dieser Datei geladen.
 *  FILENAME ist der Name der Datei, in der der geheime Schlüssel gespeichert
 *  ist. Wird NULL angegeben, so wird die Standarddatei "./privat_key.data" benutzt.
 *
 * RETURN-Code: 1 bei Erfolg, 0 sonst.
 */

int Get_Private_Key(const char *filename, mpz_t p, mpz_t w, mpz_t x)
{
	FILE *f;
	char *line = NULL;
	size_t *bufsize = malloc(sizeof(int));
	*bufsize = 0;

	if (!filename) filename = concatstrings(getenv("HOME"),"/private_key.data",NULL);
	if (!(f=fopen(filename,"r"))) {
		fprintf(stderr,"GET_PRIVATE_KEY: Kann die Datei %s nicht öffnen: %s\n",filename,strerror(errno));
		return 0;
	}
	if(getline(&line,bufsize,f) <= 0 || mpz_set_str(p, line, 16)
			|| getline(&line,bufsize,f) <= 0 || mpz_set_str(w, line, 16)
			|| getline(&line,bufsize,f) <= 0 || mpz_set_str(x, line, 16)) {
		fprintf(stderr,"GET_PRIVAT_KEY: Fehler beim Lesen der Datei %s\n",filename);
		fclose(f);
		return 0;
	}
	fclose(f);
	return 1;
}


