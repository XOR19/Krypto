/*************************************************************
**         Europäisches Institut für Systemsicherheit        *
**   Praktikum "Kryptographie und Datensicherheitstechnik"   *
**                                                           *
** Versuch 3: Brechen von EC-Karten PINs                     *
**                                                           *
**************************************************************
**
** pin.h Headerfile für den PIN-Versuch
**/

/*
* Die Funktion open_connection öffnet eine Verbindung zum Server server_id.
* Wenn server_id leer ist, so wird der Default-Server verwendet. In diff1 und
* diff2 werden die Differenzen auf der virtuellen Karte zurückgegeben.
*
* Die Funktionen try_pin testet  eine bzw. PINs auf Gültigkeit.
* War die PIN korrekt, so ist die Antwort 1, bei falscher PIN ist die
* Antwort 0. Wird die zulässige Anzahl an Versuchen überschritten, so wird 0
* zurückgegeben.
*
* Die Funktion try_pins testet mehrere PINS auf Gültigkeit. War
* die korrekte PIN in der Liste, so wird der Index dieser PIN
* zurückgegeben. Andernfalls -1. Wird die zulässige Anzahl an Versuchen
* überschritten, so wird -1 zurückgegeben.
*
* close_connection schließt die Verbindung und vernichtet die Karte.
*
* try_max gibt die maximal zulässige Versuchsanzahl zurück.
**/

void open_connection(char *server_id, int *diff1, int *diff2);
int try_pin(int pin);
int try_pins(int pin[], int npin);
int try_max(void);
void close_connection(void);
