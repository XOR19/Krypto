/*************************************************************
 **         Europäisches Institut für Systemsicherheit        *
 **   Praktikum "Kryptographie und Datensicherheitstechnik"   *
 **                                                           *
 ** Versuch 1: Klassische Chiffrierverfahren                  *
 **                                                           *
 **************************************************************
 **
 ** vigenere.c: Implementierung einer Vigenere-Chiffre
 **/

#define INC_KEY_ON_IGNORE 0

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <linux/limits.h>
#include <getopt.h>

#define MODE_ENCIPHER 0
#define MODE_DECIPHER 1

#define NUMCHARS 26         // numbers of symbols in our alphabet
#define BLOCK_SIZE 4096     // the size of blocks to process (read -> de-/encipher -> write)

#include <praktikum.h>

static inline bool isCharValid(char c) {
	return c <= 'Z' && c >= 'A';
}

static void prepareKey(const char* keyIn, char* keyOut, unsigned char mode) {
	while (*keyIn) {
		char c = *keyIn - 'A' + 1; // 1<=c<=NUMCHARS
		*keyOut = mode == MODE_DECIPHER ? NUMCHARS - c : c % NUMCHARS;
		keyIn++;
		keyOut++;
	}
	// 0<=keyOut[i]<NUMCHARS
}

static int vigenere(const char *bufIn, char *bufOut, unsigned int bufLength,
		const char *shifts, unsigned int shiftsLength,
		unsigned int initShiftsIdx) {

	char c, symbol;
	unsigned int i, idx;
	for (i = 0, idx = initShiftsIdx; i < bufLength; ++i) {
		if (!isCharValid(c = bufIn[i])) {
			bufOut[i] = c;

#if INC_KEY_ON_IGNORE
			++idx; // only advance on valid symbols except when INC_KEY_ON_IGNORE ist true
#endif

			continue;
		}

		if (idx >= shiftsLength) {
			idx = 0;
		}

		symbol = c - 'A';
		bufOut[i] = ((symbol + shifts[idx++]) % NUMCHARS) + 'A';
	}
	return idx;
}

static bool stringValid(char *str) {
	for (char *c = str; *c; ++c) {
		if (!isCharValid(*c)) {
			return false;
		}
	}
	return true;
}

static void printhelp(const char* cmd) {
	printf("Aufruf: %s [OPTION]... MODE KEY INPUT [OUTPUT]\n", cmd);
	printf("Für Compatiblitaet: %s [OPTION]... [INPUT] [OUTPUT] [KEY] [MODE]\n",
			cmd);
	printf("Optionen:\n");
	printf("  -h, --help     Diese Hilfe ausgeben und beenden\n");
	printf("  -v, --version  Versionsnummer ausgeben und beenden\n");
	printf("\n");
	printf("Mode:\n");
	printf("   e, encipher   Entschlüsseln\n");
	printf("   d, decipher   Verschlüsseln\n");
	printf("\n");
	printf(
			"Ist OUTPUT nicht spezifiziert wird die Ausgabe auf stdout umgeleitet,\n");
	printf(
			"Sind INPUT, OUTPUT, KEY, MODE in compatiblitaet nicht spezifiziert, \n");
	printf("wird der user per promt nach den daten gefragt.\n");
}

static void printshorthelp(const char* cmd) {
	printf("Aufruf: %s [OPTION]... MODE INPUT [OUTPUT]\n", cmd);
	printf("„%s --help“ liefert weitere Informationen.\n", cmd);
}

static void printversion(void) {
	printf("vigenere 1.0\n");
}

const static struct option long_options[] = {
		{ "version", no_argument, 0, 'v' },
		{ "help", no_argument, 0, 'h' },
		{0, 0, 0, 0 } };

/*
 * main(argc,argv) : Das Hauptprogramm, welches beim Aufruf von VIGENERE aufgerufen wird.
 *   ARGC ist die Anzahl der in der Kommandozeile angegebenen Argumente plus 1, ARGV ist
 *   ein Feld von Zeigern auf eben diese Argumente. ARGV[1] ist das erste usw.
 *   ARGV[0] enthält den Namen des Programms.
 */

int main(int argc, char **argv) {
	char infilename[PATH_MAX];
	char outfilename[PATH_MAX];
	String help, key;
	int mode;
	int outtostd = 0;
	/***** weitere (lokale) Hiflsbvariabeln *******/

	FILE *infile, *outfile;

	int opt;
	int option_index;
	while ((opt = getopt_long(argc, argv, "hH?vV", long_options, &option_index))
			!= -1) {

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
		}

	}

	mode = -1;
	if (optind < argc) {
		const char* mode_arg = argv[optind];
		if (mode_arg[0] == 'd') {
			if (mode_arg[1] == 0 || !strcmp(mode_arg, "decipher")) {
				mode = MODE_DECIPHER;
			}
		} else if (mode_arg[0] == 'e') {
			if (mode_arg[1] == 0 || !strcmp(mode_arg, "encipher")) {
				mode = MODE_ENCIPHER;
			}
		}
		if (mode != -1)
			optind++;
	}
	if (mode == -1) {
		// old compatiblity
		if (optind < argc) {
			strncpy(infilename, argv[optind++], sizeof(infilename));
		} else {
			readline("Eingabefile : ", infilename, sizeof(infilename));
		}
		if (optind < argc) {
			strncpy(outfilename, argv[optind++], sizeof(outfilename));
		} else {
			readline("Ausgabefile : ", outfilename, sizeof(outfilename));
		}
		if (optind < argc) {
			strncpy(key, argv[optind++], sizeof(key));
		} else {
			readline("Schluessel  : ", key, sizeof(key));
		}
		if (optind < argc) {
			const char* mode_arg = argv[optind++];
			if (mode_arg[0] == 'e'
					&& (mode_arg[1] == 0 || !strcmp(mode_arg, "encipher"))) {
				mode = MODE_ENCIPHER;
			} else if (mode_arg[0] == 'd'
					&& (mode_arg[1] == 0 || !strcmp(mode_arg, "decipher"))) {
				mode = MODE_DECIPHER;
			} else {
				fprintf(stderr,
						"FEHLER: Unbekannter Modus, 'encipher' oder 'decipher' erwartet.\n");
				exit(20);
			}
		} else {
			do {
				readline("V)er- oder E)ntschlüsseln : ", help, sizeof(help));
				string_to_upper(help);
			} while (strlen(help) != 1 && help[0] != 'V' && help[0] != 'E');
			mode = help[0] == 'E' ? MODE_ENCIPHER : MODE_DECIPHER;
		}
	} else {
		if (optind >= argc) {
			printf("KEY expected\n");
			printshorthelp(argv[0]);
			exit(1);
		}
		strncpy(key, argv[optind++], sizeof(key));
		if (optind >= argc) {
			printf("INPUT expected\n");
			printshorthelp(argv[0]);
			exit(1);
		}
		strncpy(infilename, argv[optind++], sizeof(infilename));
		if (optind < argc) {
			strncpy(outfilename, argv[optind++], sizeof(outfilename));
		} else {
			outtostd = 1;
		}
		if (optind < argc) {
			printf("Too many arguments\n");
			printshorthelp(argv[0]);
			exit(1);
		}
	}

	string_to_upper(key);

	unsigned int keyLength = strlen(key);
	if (!stringValid(key) || keyLength == 0) {
		fprintf(stderr, "FEHLER: Ungueltiger Schluessel.\n");
		exit(0xBAD);
	}

	/* Öffnen der Dateien:
	 *  `fopen' gibt im Fehlerfall einen NULL-Pointer zurück. Kann die Datei
	 *  geöffnet werden, so wird der von `fopen' zurückgelieferte FILE-Pointer
	 *  als Argument bei den Aufrufen `fgets', `fprintf', `fclose' usw.
	 *  zur Identifizierung der Datei angegeben.
	 */
	if (!(infile = fopen(infilename, "r"))) {
		fprintf(stderr,
				"FEHLER: Eingabefile %s kann nicht geöffnet werden: %s\n",
				infilename, strerror(errno));
		exit(20);
	}

	if (outtostd) {
		outfile = stdout;
	} else {
		if (!(outfile = fopen(outfilename, "w"))) {
			fprintf(stderr,
					"FEHLER: Ausgabefile %s kann nicht geöffnet werden: %s\n",
					outfilename, strerror(errno));
			exit(20);
		}
	}

	/* Belegung der Variablen:
	 *  infilename : Name der Eingabedatei
	 * outfilename : Name der Ausgabedatei
	 *      infile : `Datei-Bezeichner', der die Eingabedatei repräsentiert.
	 *     outfile : `Datei-Bezeichner', der die Ausgabedatei repräsentiert.
	 *         Key : Schlüssel, nach Großschrift gewandelt
	 *        mode : Flag, == 1 im Entschlüsselungsmodus, ansonsten 0.
	 */

	char bufferIn[BLOCK_SIZE + 1];

	bufferIn[BLOCK_SIZE] = 0; // null-terminate it so that it is also a C-string
	// even if not needed

	size_t charsRead;
	unsigned int keyIndex = 0;

	prepareKey(key, key, mode);

	do {
		charsRead = fread(bufferIn, 1, BLOCK_SIZE, infile);
		string_to_upper(bufferIn);

		keyIndex = vigenere(bufferIn, bufferIn, charsRead, key, keyLength,
				keyIndex);
		fwrite(bufferIn, 1, charsRead, outfile);

	} while (charsRead == BLOCK_SIZE);

	/* Schließen der Ein- und Ausgabedateien */
	fclose(infile);
	if (!outtostd)
		fclose(outfile);

	return 0;
}
