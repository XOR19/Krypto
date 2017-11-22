/*************************************************************
**         Europäisches Institut für Systemsicherheit        *
**   Praktikum "Kryptographie und Datensicherheitstechnik"   *
**                                                           *
** Versuch 4: Brechen der Blockchiffre FEAL                  *
**                                                           *
**************************************************************
**
** feal.h Headerfile für den Feal-Versuch
**/

/*typedef unsigned long ulong; schon in sys/types.h definiert */
typedef unsigned short uword;
typedef unsigned char ubyte;


/**********************  Prototypes  **************************/

/*
 * Feal_GS() erlaubt nur N Aufrufe mit einem festen Schlüssel. Ein
 * neuer Schlüssel wird durch Aufruf der Funktion Feal_NewKey() erzeugt.
 * Sind die maximal zulässigen Aufrufe verbraucht, liefert Feal_GS() im
 * Parameter keyoverflow 1 zurück. Die Anzahl der bis jetzt benutzten
 * Aufrufe von Feal_GS kann mit Feal_GetCount erfragt werden. Feal_GetMaxCount
 * liefert die maximal zulässige Anzahl von Aufrufen zurück -- also N.
 * Vor der Benutzung von Feal_GS müssen explizit Schlüssel mit Feal_NewKey
 * erzeugt werden!
 *
 * Feal_GS(u,v,keyoverflow) : Berechnet den Wert G'(u,v) mit den aktuellen
 *    geheimen Schlüsseln. Ist dieser "aufgebraucht", wird KEYOVERFLOW auf
 *    1 gesetzt. Feal-GS benötigt pro Aufruf ca. 1 Sekunde!
 *
 * Feal_G(k1,k2,k3,u,v) : Berechnet die G-Funktion. Diese Funktion unterliegt
 *    keiner Beschränkung!
 *
 * Feal_NewKey() : Generiert einen neuen geheimen Schlüssel für Feal_GS.
 *
 * Feal_CheckKey(k1,k2,k3) : Vergleicht k1,k2,k3 mit den internen geheimen.
 *    Nach einem Aufruf von Feal_CheckKey() muß ein neuer Satz Schlüssel mit
 *    Feal_NewKey angefordert werden, weil die Schlüssel als verbraucht
 *    markiert werden.
 *
 * Feal_GetCount(): Liefert die aktuelle Anzahl von Aufrufen von Feal_GS
 *    für den zur Zeit gültigen Schlüssel zurück.
 *
 * Feal_GetMaxCount(): Liefet die maximal zulässige Anzahl N von
 *    Feal_GS-Aufrufen mit dem gleichen Schlüssel zurück.
 */

ubyte Feal_G           (ubyte k1, ubyte k2, ubyte k3, ubyte x, ubyte y);
ubyte Feal_GS          (ubyte x, ubyte y, int *ofl);
int   Feal_CheckKey    (ubyte k1, ubyte k2, ubyte k3);
void  Feal_NewKey      (void);
int   Feal_GetCount    (void);
int   Feal_GetMaxCount (void);
