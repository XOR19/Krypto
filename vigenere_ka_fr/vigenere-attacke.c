/*************************************************************
 **         Europäisches Institut für Systemsicherheit        *
 **   Praktikum "Kryptographie und Datensicherheitstechnik"   *
 **                                                           *
 ** Versuch 1: Klassische Chiffrierverfahren                  *
 **                                                           *
 **************************************************************
 **
 ** vigenere_attacke.c: Brechen der Vigenere-Chiffre
 **/

#include <stdio.h>
#include <stdlib.h>
#include <praktikum.h>
#include <unistd.h>
#include <getopt.h>
#include <linux/limits.h>

#define NUMCHARS    26       /* Anzahl der Zeichenm, die betrachtet werden ('A' .. 'Z') */

const char *StatisticFileName = "statistik.data"; /* Filename der Wahrscheinlichkeitstabelle */
const char *WorkFile = "testtext.ciph"; /* Filename des verschlüsselten Textes */

double PropTable[NUMCHARS]; /* Tabellke mit den Zeichenwahrscheinlichkeiten.
 * ProbTable[0] == 'A', PropTable[1] == 'B' usw. */

/*--------------------------------------------------------------------------*/

/*
 * GetStatisticTable(): Liest die Statistik-Tabelle aus dem File
 * STATISTICFILENAME in das globale Array PROPTABLE ein.
 */

static void GetStatisticTable(const char* file) {
	FILE *inp;
	int i;
	char line[64];

	if (!(inp = fopen(file, "r"))) {
		fprintf(stderr, "FEHLER: File %s kann nicht geöffnet werden: %s\n",
				StatisticFileName, strerror(errno));
		exit(20);
	}

	for (i = 0; i < TABSIZE(PropTable); i++) {
		fgets(line, sizeof(line), inp);
		if (feof(inp)) {
			fprintf(stderr,
					"FEHLER: Unerwartetes Dateieine in %s nach %d Einträgen.\n",
					StatisticFileName, i);
			exit(20);
		}
		PropTable[i] = atof(line);
	}
	fclose(inp);
}

/*-------------------------------------------------------------------------*/

/* GetFile(void) : Ließt den verschlüsselten Text aus dem File
 *   WORKFILE zeichenweise in das globale Array TEXTARRAY ein und zählt
 *   TEXTLENGTH für jedes Zeichen um 1 hoch.
 *   Eingelesen werden nur Buchstaben. Satz- und Sonderzeichen werden weggeworfen,
 *   Kleinbuchstaben werden beim Einlesen in Großbuchstaben gewandelt.
 */

static char* GetFile(const char* file, int* length) {
	FILE *inp;
	char c;

	if (!(inp = fopen(file, "r"))) {
		fprintf(stderr, "FEHLER: File %s kann nicht geöffnet werden: %s\n",
				WorkFile, strerror(errno));
		exit(20);
	}

	fseek(inp, 0L, SEEK_END);
	long int size = ftell(inp);
	fseek(inp, 0L, SEEK_SET);

	if (size > 1048576)
		size = 1048576;
	char* buf = (char*) malloc(size + 1);
	if (!buf) {
		fprintf(stderr, "FEHLER: Buffer konnte nicht allokiert werden\n");
		exit(20);
	}
	int i = 0;
	while (!feof(inp) && i < size) {
		c = fgetc(inp);
		if (feof(inp))
			break;
		if (c >= 'a' && c <= 'z')
			c -= 32;
		if (c >= 'A' && c <= 'Z') {
			buf[i++] = c;
		}
	}
	fclose(inp);
	buf[i] = 0;
	if (length)
		*length = i;
	return buf;
}

/*--------------------------------------------------------------------------*/

/*
 * CountChars( int start, int offset, int h[] )
 *
 * CountChars zählt die Zeichen (nur Buchstaben!) im globalen Feld
 * TEXTARRAY. START gibt an, bei welchen Zeichen (Offset vom Begin der
 * Tabelle) die Zählung beginnen soll und OFFSET ist die Anzahl der
 * Zeichen, die nach dem 'Zählen' eines Zeichens weitergeschaltet
 * werden soll. 'A' wird in h[0], 'B' in h[1] usw. gezählt.
 *  
 *  Beispiel:  OFFSET==3, START==1 --> 1,  4,  7,  10, ....
 *             OFFSET==5, START==3 --> 3,  8, 13,  18, ....
 *
 * Man beachte, daß das erste Zeichen eines C-Strings den Offset 0 besitzt!
 */

static void CountChars(const char* text, int textLength, int start, int offset,
		int h[NUMCHARS]) {
	int i;
	char c;

	for (i = 0; i < NUMCHARS; i++)
		h[i] = 0;

	/*****************  Aufgabe  *****************/
	for (i = start; i < textLength && i >= 0; i += offset) {
		c = text[i];
		h[c - 'A']++;
	}
}

static int GetKey(int h[NUMCHARS], int n, double* conf) {
	int i;
	int off;
	int min = -1;
	double min_err = 1e100;
	for (off = 0; off < NUMCHARS; off++) {
		double err = 0;
		for (i = 0; i < NUMCHARS; i++) {
			double e = h[(i + off) % NUMCHARS];
			e /= n;
			e -= PropTable[i];
			err += e * e; // Quadratischer fehler minimieren
		}
		if (err < min_err) {
			min_err = err;
			min = off;
		}
	}
	if (conf)
		*conf = min_err;
	return min == 0 ? 'Z' : min - 1 + 'A';
}

static void printhelp(const char* cmd) {
	printf("Aufruf: %s [OPTION]... INPUT [OUTPUT]\n", cmd);
	printf("Optionen:\n");
	printf("  -h, --help        Diese Hilfe ausgeben und beenden\n");
	printf("  -v, --version     Versionsnummer ausgeben und beenden\n");
	printf("  -s, --statistics  Statistics file\n");
	printf("\n");
	printf(
			"Ist OUTPUT nicht spezifiziert wird die Ausgabe auf stdout umgeleitet,\n");
	printf("ist INPUT nicht spezifiziert wird testtext.ciph angenommen.\n");
}

static void printshorthelp(const char* cmd) {
	printf("Aufruf: %s [OPTION]... INPUT [OUTPUT]\n", cmd);
	printf("„%s --help“ liefert weitere Informationen.\n", cmd);
}

static void printversion(void) {
	printf("vigenere-attacke 1.0\n");
}

const static struct option long_options[] = {
		{ "version", no_argument, 0, 'v' }, { "help", no_argument, 0, 'h' }, {
				"statistics", required_argument, 0, 's' }, { 0, 0, 0, 0 } };
/*------------------------------------------------------------------------------*/

int main(int argc, char **argv) {

	char statisticFileName[PATH_MAX];
	char infile[PATH_MAX];
	char outfile[PATH_MAX];
	strcpy(statisticFileName, "statistik.data");

	int opt;
	int option_index;
	while ((opt = getopt_long(argc, argv, "hH?vVs:", long_options,
			&option_index)) != -1) {

		switch (opt) {
		case 'h':
		case 'H':
		case '?':
			printhelp(argv[0]);
			exit(0);
		case 'v':
		case 'V':
			printversion();
			exit(0);
		case 's':
			strncpy(statisticFileName, optarg, sizeof(statisticFileName));
			break;
		}

	}

	const char* outparam;

	if (optind < argc) {
		strncpy(infile, argv[optind++], sizeof(infile));
	} else {
		strncpy(infile, WorkFile, sizeof(infile));
	}

	if (optind < argc) {
		outparam = outfile;
		strncpy(outfile, argv[optind++], sizeof(outfile));
	} else {
		outparam = 0;
	}

	if (optind < argc) {
		printf("Too many arguments\n");
		printshorthelp(argv[0]);
		exit(1);
	}

	GetStatisticTable(statisticFileName);/* Wahrscheinlichkeiten einlesen */

	int length;
	char* data = GetFile(infile, &length); /* zu bearbeitendes File einlesen */

	/*****************  Aufgabe  *****************/
	int h[NUMCHARS];
	CountChars(data, length, 0, 1, h);
	double I_c = 0;
	int i;
	for (i = 0; i < NUMCHARS; i++) {
		double v = h[i] / (double) length;
		I_c += v * v;
	}
	double I_c_rand = 1.0 / NUMCHARS;
	double I_c_eng = 0.065;

	double v = (I_c - I_c_rand) / (I_c_eng - I_c_rand); //==(n-l)/(l(n-1))
	double l = length / (v * (length + 1) + 1);

	printf("l: %f\n", l);

	int roundedL = (int) (l + 0.5);
	int curr = roundedL;
	int next = curr + 1;
	int up = -1;
	char keybuf[length + 1];

	while (next >= 0 && curr <= length) {
		double conf;
		double confm = 0;
		for (i = 0; i < curr; i++) {
			CountChars(data, length, i, curr, h);
			int c = GetKey(h, length / curr, &conf);
			confm += conf;
			keybuf[i] = c;
		}
		keybuf[curr] = 0;
		confm /= curr;
		printf("Key for len %i with error %f:%s\n", curr, confm, keybuf);
		if (confm < 0.015) { // Can be done better?
			free(data);
			printf("Likely Key:%s\n", keybuf);
			execl("vigenere", "vigenere", "d", keybuf, infile, outparam, NULL);
			return 0;
		}

		int tmp = curr;
		curr = next;
		next = tmp;
		next += up;
		up = -up;
	}
	free(data);
	printf("nothing found\n");

	return 0;
}
