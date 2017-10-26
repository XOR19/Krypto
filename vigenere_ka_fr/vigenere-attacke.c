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


// Bad workaround for today
#define __gmplib_h
typedef int mpz_t;

#define ASSERT(xx)

#include <stdio.h>
#include <stdlib.h>
#include <praktikum.h>

#define NUMCHARS    26       /* Anzahl der Zeichenm, die betrachtet werden ('A' .. 'Z') */
#define MaxFileLen  32768    /* Maximale Größe des zu entschlüsselnden Textes */

const char *StatisticFileName = "statistik.data";  /* Filename der Wahrscheinlichkeitstabelle */
const char *WorkFile          = "testtext.ciph";   /* Filename des verschlüsselten Textes */

double PropTable[NUMCHARS]; /* Tabellke mit den Zeichenwahrscheinlichkeiten.
			     * ProbTable[0] == 'A', PropTable[1] == 'B' usw. */
char TextArray[MaxFileLen]; /* die eingelesene Datei */
int TextLength;             /* Anzahl der gültigen Zeichen in TextArray */

/*--------------------------------------------------------------------------*/

/*
 * GetStatisticTable(): Liest die Statistik-Tabelle aus dem File
 * STATISTICFILENAME in das globale Array PROPTABLE ein.
 */

static void GetStatisticTable(void)
  {
    FILE *inp;
    int i;
    char line[64];

    if (!(inp=fopen(StatisticFileName,"r"))) {
      fprintf(stderr,"FEHLER: File %s kann nicht geöffnet werden: %s\n",
	      StatisticFileName,strerror(errno));
      exit(20);
    }

    for (i=0; i<TABSIZE(PropTable); i++) {
      fgets(line,sizeof(line),inp);
      if (feof(inp)) {
        fprintf(stderr,"FEHLER: Unerwartetes Dateieine in %s nach %d Einträgen.\n",
		StatisticFileName,i);
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

static void GetFile(void)
  {
    FILE *inp;
    char c;

    if (!(inp=fopen(WorkFile,"r"))) {
      fprintf(stderr,"FEHLER: File %s kann nicht geöffnet werden: %s\n",
	      WorkFile,strerror(errno));
      exit(20);
    }

    TextLength=0;
    while (!feof(inp)) {
      c = fgetc(inp);
      if (feof(inp)) break;
      if (c>='a' && c<='z') c -= 32;
      if (c>='A' && c<='Z') {
	if (TextLength >= sizeof(TextArray)) {
	  fprintf(stderr,"FEHLER: Eingabepuffer nach %d Zeichen übergelaufen!\n",TextLength);
	  exit(20);
	}
        TextArray[TextLength++] = c;
      }
    }
    fclose(inp);
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

static void CountChars( int start, int offset, int h[NUMCHARS])
  {
    int i;
    char c;

    for (i=0; i<NUMCHARS; i++) h[i] = 0;

    /*****************  Aufgabe  *****************/
    for(i=start; i<TextLength && i>=0; i+=offset){
    	c = TextArray[i];
    	ASSERT(c>='A' && c<='Z')
    	h[c-'A']++;
    }
  }


/*------------------------------------------------------------------------------*/

int main(int argc, char **argv)
{

  GetStatisticTable();     /* Wahrscheinlichkeiten einlesen */
  GetFile();               /* zu bearbeitendes File einlesen */

  /*****************  Aufgabe  *****************/
  int h[NUMCHARS];
  CountChars(0, 1, h);
  double I_c = 0;
  int i;
  for(i=0; i<NUMCHARS; i++){
	  double v = h[i]/(double)TextLength;
	  I_c += v*v;
  }
  double I_c_rand = 1.0/NUMCHARS;
  double I_c_eng = 0.065;

  double v = (I_c-I_c_rand)/(I_c_eng-I_c_rand); //==(n-l)/(l(n-1))
  double l = TextLength/(v*(TextLength+1)+1);

  printf("l: %f\n", l);

  return 0;
}
