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

// Bad workaround for today
#define __gmplib_h

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>

typedef int mpz_t;

#define MODE_ENCIPHER 0
#define MODE_DECIPHER 1

#define NUMCHARS 26         // numbers of symbols in our alphabet
#define BLOCK_SIZE 4096     // the size of blocks to process (read -> de-/encipher -> write)

#include <praktikum.h>

/*********************  Globale Hilfsbvariabeln  *******************/
String Key;     /* Schlüssel */
int keyPos;

/*
 * int Encipher(int c) : Interpretiert C als Zeichen, verschlüsselt es nach der
 *                       Methode von Vigenere und gibt das Ergebnis als Resultat
 *                       zurück.
 */

static int Encipher(int c) {

#if !INC_KEY_ON_IGNORE
	if(c>='A' && c<='Z') {
#endif

		int keyC = Key[keyPos++];
		if(!keyC){
			keyC = Key[0];
			keyPos = 1;
		}

#if INC_KEY_ON_IGNORE
	if(c>='A' && c<='Z') {
#endif

		int move = (keyC - 'A' + 1)%26; // 'Z' würde probleme machen

		c += move;
		if(c>'Z')
			c -= 26;  // 'Z' - 'A'
	}

	return c;
  }


/*
 * int Decipher(int c) : Interpretiert C als Zeichen, entschlüsselt es nach der
 *                       Methode von Vigenere und gibt das Ergebnis als Resultat
 *                       zurück.
 */

static int Decipher(int c) {

#if !INC_KEY_ON_IGNORE
	if(c>='A' && c<='Z') {
#endif

		int keyC = Key[keyPos++];
		if(!keyC){
			keyC = Key[0];
			keyPos = 1;
		}

#if INC_KEY_ON_IGNORE
	if(c>='A' && c<='Z') {
#endif

		int move = (keyC - 'A' + 1)%26; // 'Z' würde probleme machen

		c -= move;
		if(c<'A')
			c += 26;  // 'Z' - 'A'

	}

	return c;
  }
  
static unsigned int mathMod(int n, unsigned int mod) {
    n %= mod;
    return n < 0 ? n + mod : n;
}

static inline bool isCharValid(char c) {
    return c <= 'Z' && c >= 'A';
}

static inline char charToSymbol(char c) {
    return c - 'A' + 1;
}

static inline char symbolToChar(char c) {
    return c + 'A' - 1;
}

static void vigenere(const char *bufIn, char *bufOut, unsigned int bufLength, const char *key, unsigned int initKeyIdx, unsigned char mode) {
    int keyLength = strlen(key);
    char *shifts = (char *) malloc(keyLength * sizeof(char));
    
    for (int i = 0; i < keyLength; ++i) {
        // the key symbols have a sign
        shifts[i] = mode == MODE_DECIPHER ? -charToSymbol(key[i]) : charToSymbol(key[i]);
    }
    
    char c, symbol;
    for (unsigned int i = 0, idx = initKeyIdx; i < bufLength; ++i) {
        if (!isCharValid(c = bufIn[i])) {
            bufOut[i] = bufIn[i]; 
            
            #if INC_KEY_ON_IGNORE 
                ++idx; // only advance on valid symbols except when INC_KEY_ON_IGNORE ist true
            #endif
            
            continue;
        }
        
        if (idx >= keyLength) {
            idx = 0;
        }
        
        symbol = charToSymbol(c);
        bufOut[i] = symbolToChar(mathMod(symbol + shifts[idx++], NUMCHARS));
    } 
}

static bool stringValid(char *str) {
    for (char *c = str; *c; ++c) {
        if (!isCharValid(*c)) {
            return false;
        }
    }
    return true;
}


/*
 * main(argc,argv) : Das Hauptprogramm, welches beim Aufruf von VIGENERE aufgerufen wird.
 *   ARGC ist die Anzahl der in der Kommandozeile angegebenen Argumente plus 1, ARGV ist
 *   ein Feld von Zeigern auf eben diese Argumente. ARGV[1] ist das erste usw.
 *   ARGV[0] enthält den Namen des Programms.
 */

int main(int argc, char **argv)
{
  String infilename, outfilename, help, zeile;
  int mode;
  /***** weitere (lokale) Hiflsbvariabeln *******/

  FILE *infile, *outfile;

  /* Wenn die Ein- bzw. Ausgabedatei oder der Schlüssel nicht in der
   * Kommandozeile angegeben wurden, fragen wir einfach nach .... */
  if (argc<2) {
      readline("Eingabefile : ", infilename, sizeof(infilename));
  } else {
      strncpy(infilename, argv[1], sizeof(infilename));
  } if (argc<3) {
      readline("Ausgabefile : ", outfilename, sizeof(outfilename));
  } else {
      strncpy(outfilename, argv[2], sizeof(outfilename));
  } if (argc<4) {
      readline("Schluessel  : ", Key,sizeof(Key));      
  } else {
      strncpy(Key, argv[3], sizeof(Key));
  }

  if (argc<5) {
    do {
      readline("V)er- oder E)ntschlüsseln : ",help,sizeof(help));
      string_to_upper(help);
    }
    while (strlen(help)!=1 && help[0]!='V' && help[0]!='E');
    mode = help[0]=='E';
  } else {
    if (!strncmp(argv[4],"encipher",strlen(argv[4]))) {
        mode = 0;
    } else if (!strncmp(argv[4],"decipher",strlen(argv[4]))) {
        mode = 1;
    } else {
      fprintf(stderr,"FEHLER: Unbekannter Modus, 'encipher' oder 'decipher' erwartet.\n");
      exit(20);
    }
  }
  string_to_upper(Key);
  
  unsigned int keyLength = strlen(Key);
  if (!stringValid(Key) || keyLength == 0) {
      fprintf(stderr, "FEHLER: Ungueltiger Schluessel.\n");
      exit(0xBAD);
  }

  /* Öffnen der Dateien:
   *  `fopen' gibt im Fehlerfall einen NULL-Pointer zurück. Kann die Datei
   *  geöffnet werden, so wird der von `fopen' zurückgelieferte FILE-Pointer
   *  als Argument bei den Aufrufen `fgets', `fprintf', `fclose' usw. 
   *  zur Identifizierung der Datei angegeben.
   */
  if (!(infile=fopen(infilename,"r"))) {
    fprintf(stderr,"FEHLER: Eingabefile %s kann nicht geöffnet werden: %s\n",infilename,strerror(errno));
    exit(20);
  }
  
  if (!(outfile=fopen(outfilename,"w"))) {
    fprintf(stderr,"FEHLER: Ausgabefile %s kann nicht geöffnet werden: %s\n",outfilename,strerror(errno));
    exit(20);
  }

  /* Belegung der Variablen:
   *  infilename : Name der Eingabedatei 
   * outfilename : Name der Ausgabedatei
   *      infile : `Datei-Bezeichner', der die Eingabedatei repräsentiert.
   *     outfile : `Datei-Bezeichner', der die Ausgabedatei repräsentiert.
   *         Key : Schlüssel, nach Großschrift gewandelt
   *        mode : Flag, == 1 im Entschlüsselungsmodus, ansonsten 0.
   */

  //*
  keyPos = 0;
  do {
    fgets(zeile,sizeof(zeile),infile);
    if (!feof(infile)) {
      strip_crlf(zeile);
      string_to_upper(zeile);

      char* ptr = zeile;
      while(*ptr){
    	  *ptr = mode?Decipher(*ptr):Encipher(*ptr);
    	  ptr++;
      }

      fprintf(outfile,"%s\n",zeile);
    }
  }
  while (!feof(infile));
  //*/
  
  /*
  char bufferIn[BLOCK_SIZE + 1];
  char bufferOut[BLOCK_SIZE];
  
  bufferIn[BLOCK_SIZE] = 0; // null-terminate it so that it is also a C-string
  
  size_t charsRead;
  unsigned int keyIndex = 0;
  do {
      charsRead = fread(bufferIn, 1, BLOCK_SIZE, infile);
      string_to_upper(bufferIn);
      
      vigenere(bufferIn, bufferOut, charsRead, Key, keyIndex, mode);
      fwrite(bufferOut, 1, charsRead, outfile);
      
      keyIndex = (keyIndex + BLOCK_SIZE) % keyLength;
  } while (charsRead == BLOCK_SIZE);
  //*/
  
  /* Schließen der Ein- und Ausgabedateien */
  fclose(infile);
  fclose(outfile);

  return 0;
}
