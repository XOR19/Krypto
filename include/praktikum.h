/*************************************************************
**         Europäisches Institut für Systemsicherheit        *
**   Praktikum "Kryptographie und Datensicherheitstechnik"   *
**                                                           *
** Praktikum-Support-Library                                 *
**                                                           *
**************************************************************
**
** praktikum.h: Prototypes der Hilfsfunktionen, nützliche Makros
**/

#ifndef _PRAKTIKUM_H
#  define _PRAKTIKUM_H

/******************************************************************************/
/*                      System-Header-Dateien einlesen                        */
/******************************************************************************/
#  ifndef FILE
#    include <stdio.h>
#  endif
#  ifndef __stdlib_h
#    include <stdlib.h>
#  endif
#  ifndef __string_h
#    include <string.h>
#  endif
#  ifndef _errno_h
#    include <errno.h>
#  endif
#  ifndef __gmplib_h
#    include <gmp.h>
#  endif

/******************************************************************************/
/*                      Einige globalen Typen und Makros                      */
/******************************************************************************/
#define STRINGLEN        256      /* Länge von 'handelsüblichen' Strings */
#define BYTELEN       	  256      /* Anzahl an mit einem Byte darstellbaren Zahlen */
#define MPZLEN     	  129      /* Anzahl an Bytes, welche in einer 2048-Bit-Langzahl reinpassen */

typedef char String[STRINGLEN];

/* quickfix: folgende constanten an linux angepasst */

typedef unsigned char UBYTE;
typedef unsigned short UWORD;
typedef unsigned int ULONG;
typedef unsigned int HalfWord;
typedef unsigned short QuarterWord;
typedef char BYTE;
typedef short WORD;
typedef int LONG;
#define LOWBYTEFIRST
#define ANSI
#define ANSIINCLUDE

#define TABSIZE(t) (sizeof(t)/sizeof(*t)) /* Gibt Anzahl der Einträge einer Tabelle zurück */

/******************************************************************************/
/*                         String-Funktionen                                  */
/******************************************************************************/

/* string_to_lower(s): Konvertiert S nach Kleinschrift */
extern void string_to_lower(char *s);

/* string_to_upper(s): Konvertiert S nach Großschrift */
extern void string_to_upper(char *s);

/* strip_crlf(s): Entfernt vom Ende des Strings CR und LF */
extern void strip_crlf(char *s);

/* conectstrings(s1,s2,s3,...,NULL) gibt einen Zeiger auf die
 *    zusammengefaßten Strings S1 usw. zurück. */
extern char *concatstrings(const char *s1,...);


/******************************************************************************/
/*                       Ein- und Ausgabe Funktionen                          */
/******************************************************************************/

/* readstring(prompt,buffer,buffersize) : Liest einen String der maximalen
 *    Länge SIZE-2 nach BUFFER von der Standardeingabe ein. Zuvor wird
 *    PROMPT ausgegeben. Das abschließende LF wird nicht mit zurückgegeben.
 */
extern void readstring(const char *prompt, char *buffer, int size);

/* int readint(prompt) : Gibt (optional) prompt aus und liest von der
 *    Standardeingabe ein Integer (-2^31 .. 2^31 - 1) ein und gibt dieses
 *    als Ergebnis zurück. Handelt es sich bei der Eingabe nicht um eine
 *    korrekte Zahl, so gibt readint() "????" aus und wiederholt die Eingabe.
 *    Die Zahl kann dezimal, Hexadezimal (mit führendem `0x') oder oktal (mit
 *    führender `0') angegeben werden.
 */
extern int readint(const char *prompt);

/* double readdouble(prompt) : Gibt (optional) prompt aus und liest eine
 *    (dezimale!) Fließkommazahl von der Standardeingabe ein und gibt sie als Ergebnis
 *    zurück. Handelt es sich bei der Eingabe nicht um eine
 *    korrekte Zahl, so gibt readint() "????" aus und wiederholt die Eingabe.
 */
extern double readdouble(const char *prompt);

/* char readchar(const char *prompt): Gibt (optional) prompt aus und liest
 *    ein einzelnes Zeichen von der Standardeingabe. Im Gegensatz zu den
 *    vorhergehenden Routinen benötigt readchar kein die Eingabe abschließendes
 *    Enter!
 */
extern char readchar(const char *prompt);

/* Kompatibilität zur Vorgänger-Version der Bibliothek */
#define readline(prompt,buffer,size) readstring(prompt,buffer,size)

/******************************************************************************/
/*                 Datentypen und Funktionen für den DES                      */
/******************************************************************************/

#define DES_DATA_WIDTH  8  /* Breite des DES in Bytes     */

typedef UBYTE DES_key[DES_DATA_WIDTH];  /* User-key                    */
typedef UBYTE DES_data[DES_DATA_WIDTH]; /* Ein- und Ausgabedaten       */
typedef ULONG DES_ikey[128/4];          /* Schlssel nach Aufbereitung */

/* DES_GenKeys erzeugt aus dem 8 Byte langen Schlüssen KEY den internen Schlüssel-
 * satz IKEY, der zum Vr- (DECODEFLG==0) bzw. entschlüsseln (DECODEFLG!=0)
 * in DES_Cipher angegeben werden muß. */
extern void   DES_GenKeys( const DES_key key, int decodeflg, DES_ikey ikey );

/* DES_Cipher ver- bzw. entschlüsselt 8 Bytes von INP nach OUT (Überlappung ist
 * zulässig). IKEY ist der Schlüssel in der internen Form, wie er mit DES_GenKeys
 * erzeugt wurde. */
extern void   DES_Cipher( const DES_ikey key, const DES_data inp, DES_data out );

/* DES_ECB ver- bzw. entschlüsselt LEN Bytes von SRC nach DST im
 * Electronic Codebook Mode. LEN muß durch 8 teilbar sein. */
extern void DES_ECB(const DES_ikey ikey,const UBYTE *src,int len,UBYTE *dst);

/* DES_CBC_Enc verschlüsselt LEN Bytes von SRC nach DST mit
 * Initialisierungsvektor IV im Cipher Block Chaining Mode. IKEY muß
 * für Verschlüsseln generiert worden sein. LEN muß durch 8 teilbar
 * sein. */
extern void DES_CBC_Enc(const DES_ikey ikey, DES_data iv, const UBYTE *src, int len, UBYTE *dst);

/* DES_CBC_Dec entschlüsselt LEN Bytes von SRC nach DST mit
 * Initialisierungsvektor IV im Cipher Block Chaining Mode. IKEY muß
 * für Entschlüsseln generiert worden sein. LEN muß durch 8 teilbar
 * sein. */
extern void DES_CBC_Dec(const DES_ikey ikey, DES_data iv, const UBYTE *src, int len, UBYTE *dst);

/* DES_OFB ver- bzw. entschlüsselt LEN Bytes von SRC nach DST im
 * Output Feedback Mode (Rückkopplungsbreite: * Bytes). LEN muß NICHT
 * durch 8 teilbar sein! */
void DES_OFB(const DES_ikey ikey, DES_data iv, const UBYTE *src, int len, UBYTE *dst);

/* DES_CFB_Enc/DES_CFB_Dec ver- und entschlüsseln im CFB-Modus. IKEY
 * für beide Funktionen zum Verschlüsseln generiert worden sein. Der
 " Schiebefaktor" beträgt 1, d.h. LEN kann beliebig sein. */
extern void DES_CFB_Enc(const DES_ikey ikey,DES_data iv,const UBYTE *src,int len,UBYTE *dst);
extern void DES_CFB_Dec(const DES_ikey ikey,DES_data iv,const UBYTE *src,int len,UBYTE *dst);

/******************************************************************************/
/*                           Diverses                                         */
/******************************************************************************/

/* RandomNumber() erzeugt eine 32-Bit breite Zufallszahl */
extern ULONG RandomNumber(void);

/* CurrentTime()ibt die aktuelle Uhrzeit in 1/1000 Sekunden seit
 * dem 1. Januar 1980 zurück. */
extern ULONG GetCurrentTime(void);

/* Ausgabe von Datum und Uhrzeit als String */
extern const char *Now(void);

/******************************************************************************/
/*                           GMP-LIB Hilfsfunktionen                          */
/******************************************************************************/

/* Konvertiert eine gegebene Langzahl in einen UBYTE-Array */
extern UBYTE * mpz_t2Ubyte(mpz_t a, unsigned int ubyteSize);

/*
 ***********************************************************************
 ** md5.h -- header file for implementation of MD5                    **
 ** RSA Data Security, Inc. MD5 Message-Digest Algorithm              **
 ** Created: 2/17/90 RLR                                              **
 ** Revised: 12/27/90 SRD,AJ,BSK,JT Reference C version               **
 ** Revised (for MD5): RLR 4/27/91                                    **
 **   -- G modified to have y&~z instead of y&z                       **
 **   -- FF, GG, HH modified to add in last register done             **
 **   -- Access pattern: round 2 works mod 5, round 3 works mod 3     **
 **   -- distinct additive constant for each step                     **
 **   -- round 4 added, working mod 7                                 **
 ***********************************************************************
 */

/*
 * Edited 7 May 93 by CP to change the interface to match that
 * of the MD5 routines in RSAREF.  Due to this alteration, this
 * code is "derived from the RSA Data Security, Inc. MD5 Message-
 * Digest Algorithm".  (See below.)  Also added argument names
 * to the prototypes.
 */

/*
 ***********************************************************************
 ** Copyright (C) 1990, RSA Data Security, Inc. All rights reserved.  **
 **                                                                   **
 ** License to copy and use this software is granted provided that    **
 ** it is identified as the "RSA Data Security, Inc. MD5 Message-     **
 ** Digest Algorithm" in all material mentioning or referencing this  **
 ** software or this function.                                        **
 **                                                                   **
 ** License is also granted to make and use derivative works          **
 ** provided that such works are identified as "derived from the RSA  **
 ** Data Security, Inc. MD5 Message-Digest Algorithm" in all          **
 ** material mentioning or referencing the derived work.              **
 **                                                                   **
 ** RSA Data Security, Inc. makes no representations concerning       **
 ** either the merchantability of this software or the suitability    **
 ** of this software for any particular purpose.  It is provided "as  **
 ** is" without express or implied warranty of any kind.              **
 **                                                                   **
 ** These notices must be retained in any copies of any part of this  **
 ** documentation and/or software.                                    **
 ***********************************************************************
 */



/* typedef a 32-bit type */
/* quickfix. Das hier sollte besser in einer globalen Definition stehen  */
#ifdef __linux
typedef unsigned int UINT4;
#else
typedef unsigned long int UINT4;
#endif

/* Data structure for MD5 (Message-Digest) computation */
typedef struct {
  UINT4 buf[4];                                    /* scratch buffer */
  UINT4 i[2];                   /* number of _bits_ handled mod 2^64 */
  unsigned char in[64];                              /* input buffer */
} MD5_CTX;

void MD5Init(MD5_CTX *mdContext);
void MD5Update(MD5_CTX *mdContext, unsigned const char *inbuf, unsigned int len);
void MD5Final(unsigned char digest[16], MD5_CTX *mdContext);
void Transform(UINT4 *buf, UINT4 *in);

#endif
