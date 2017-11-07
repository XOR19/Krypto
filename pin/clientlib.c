struct in_addr;

#include <sys/types.h>

#include <arpa/inet.h>
#include <netinet/in.h>

#include <sys/socket.h>

#include <errno.h>
#include <netdb.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define DEFAULT_HOST "poincare.ira.uka.de"
/*#define DEFAULT_HOST "localhost"*/
#define DEFAULT_PORT 6453

#include "pin.h"

static int sd = -1;

static unsigned char msgbuf[16];

/* typedef int in_addr_t; */

/*	$OpenBSD: inet_addr.c,v 1.5 1997/04/05 21:13:10 millert Exp $	*/

/*
 * ++Copyright++ 1983, 1990, 1993
 * -
 * Copyright (c) 1983, 1990, 1993
 *    The Regents of the University of California.  All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 * 	This product includes software developed by the University of
 * 	California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 * -
 * Portions Copyright (c) 1993 by Digital Equipment Corporation.
 * 
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies, and that
 * the name of Digital Equipment Corporation not be used in advertising or
 * publicity pertaining to distribution of the document or software without
 * specific, written prior permission.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS" AND DIGITAL EQUIPMENT CORP. DISCLAIMS ALL
 * WARRANTIES WITH REGARD TO THIS SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS.   IN NO EVENT SHALL DIGITAL EQUIPMENT
 * CORPORATION BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL
 * DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR
 * PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS
 * ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS
 * SOFTWARE.
 * -
 * --Copyright--
 */

/* snip */

/* 
 * Check whether "cp" is a valid ascii representation
 * of an Internet address and convert to a binary address.
 * Returns 1 if the address is valid, 0 if not.
 * This replaces inet_addr, the return value from which
 * cannot distinguish between failure and a local broadcast address.
 */
int
inet_aton(cp, addr)
	register const char *cp;
	struct in_addr *addr;
{
	register in_addr_t val;
	register int base, n;
	register char c;
	u_int parts[4];
	register u_int *pp = parts;

	c = *cp;
	for (;;) {
		/*
		 * Collect number up to ``.''.
		 * Values are specified as for C:
		 * 0x=hex, 0=octal, isdigit=decimal.
		 */
		if (!isdigit(c))
			return (0);
		val = 0; base = 10;
		if (c == '0') {
			c = *++cp;
			if (c == 'x' || c == 'X')
				base = 16, c = *++cp;
			else
				base = 8;
		}
		for (;;) {
			if (isascii(c) && isdigit(c)) {
				val = (val * base) + (c - '0');
				c = *++cp;
			} else if (base == 16 && isascii(c) && isxdigit(c)) {
				val = (val << 4) |
					(c + 10 - (islower(c) ? 'a' : 'A'));
				c = *++cp;
			} else
				break;
		}
		if (c == '.') {
			/*
			 * Internet format:
			 *	a.b.c.d
			 *	a.b.c	(with c treated as 16 bits)
			 *	a.b	(with b treated as 24 bits)
			 */
			if (pp >= parts + 3)
				return (0);
			*pp++ = val;
			c = *++cp;
		} else
			break;
	}
	/*
	 * Check for trailing characters.
	 */
	if (c != '\0' && (!isascii(c) || !isspace(c)))
		return (0);
	/*
	 * Concoct the address according to
	 * the number of parts specified.
	 */
	n = pp - parts + 1;
	switch (n) {

	case 0:
		return (0);		/* initial nondigit */

	case 1:				/* a -- 32 bits */
		break;

	case 2:				/* a.b -- 8.24 bits */
		if (val > 0xffffff)
			return (0);
		val |= parts[0] << 24;
		break;

	case 3:				/* a.b.c -- 8.8.16 bits */
		if (val > 0xffff)
			return (0);
		val |= (parts[0] << 24) | (parts[1] << 16);
		break;

	case 4:				/* a.b.c.d -- 8.8.8.8 bits */
		if (val > 0xff)
			return (0);
		val |= (parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8);
		break;
	}
	if (addr)
		addr->s_addr = htonl(val);
	return (1);
}

void open_connection(char *server_id, int *diff1, int *diff2, const char* username, int uid)
{
	struct sockaddr_in sin;
	char *hostname = DEFAULT_HOST;
	int port = DEFAULT_PORT;
	char *t,*s;
	struct hostent *h;
	char *login;

	if (sd >= 0) {
		fprintf(stderr, "Fatal: Tried to open connection twice\n");
		exit(2);
	}
	if (server_id) {
		t = strrchr(server_id, ':');
		if (t == 0) /* only hostname */
			hostname = server_id;
		else {
			*t++ = 0;
			hostname = server_id;
			port = atoi(t);
		}
	}
	/* test schnittstelle */
	if (s=getenv("EISS_PIN_SERVERHOST")) {
	  hostname = strdup(s);
	}
	sd = socket(AF_INET, SOCK_STREAM, 0);
	h = gethostbyname(hostname);
	if (h == 0) {
		if (!inet_aton(hostname, &(sin.sin_addr))) {
			fprintf(stderr, "Fatal: Unknown host %s\n", hostname);
			exit(2);
		}
	} else {
		sin.sin_addr.s_addr = *((int *)(h->h_addr));
	}
	sin.sin_port = htons(port);
	sin.sin_family = AF_INET;
	if (connect(sd, &sin, sizeof(sin)) < 0) {
		perror("connect");
		exit(2);
	}
	memset(msgbuf, 0, 16);
	login = username;
	strncpy(msgbuf+8, login, 8);
	*((int *)(msgbuf+4)) = htonl(uid);
	msgbuf[3] = 0x00;
	if (write(sd, msgbuf+3, 13) != 13) {
		perror("write");
		exit(2);
	}
	if (read(sd, msgbuf+1, 5) != 5) {
		perror("read");
		exit(2);
	}
	if (msgbuf[1] != 0x80) {
		fprintf(stderr, "Fatal: invalid response\n");
		exit(2);
	}
	*diff1 = ntohs(*((short *)(msgbuf+2)));
	*diff2 = ntohs(*((short *)(msgbuf+4)));
}

int try_pins(int pin[], int npin)
{
	char *pinbuf;
	int i;

	if (sd < 0) {
		fprintf(stderr, "Fatal: try_pins w/o connection\n");
		exit(2);
	}
	pinbuf = malloc(npin*2);
	if (!pinbuf) {
		fprintf(stderr, "Fatal: out of memory\n");
		exit(2);
	}
	for (i = 0; i < npin; i++) {
		*((short *)(pinbuf+2*i)) = htons(pin[i]);
	}
	msgbuf[3] = 1;
	*((int *)(msgbuf+4)) = htonl(npin);
	if (5 != write(sd, msgbuf+3, 5) || 2*npin != write(sd, pinbuf,
	    2*npin)) {
		perror("write");
		exit(2);
	}
	free(pinbuf);
	if (2 != read(sd, msgbuf, 2)) {
		perror("read");
		exit(2);
	}
	if (msgbuf[0] != 0x81) {
		fprintf(stderr, "Fatal: invalid response\n");
		exit(2);
	}
	if (msgbuf[1] == 0)
		return (-1);
	else if (msgbuf[1] == 1) {
		if (4 != read(sd, msgbuf, 4)) {
			perror("read");
			exit(2);
		}
		return ntohl(*((int *)msgbuf));
	} else if (msgbuf[1] == 2) {
		if (4 != read(sd, msgbuf, 4)) {
			perror("read");
			exit(2);
		}
		return -1;
	} else {
		fprintf(stderr, "Fatal: invalid response\n");
		exit(2);
	}
}

int try_pin(int pin)
{
	return (1+(try_pins(&pin, 1)));
}

int try_max(void)
{
	if (sd < 0) {
		fprintf(stderr, "Fatal: try_max w/o connection\n");
		exit(2);
	}
	msgbuf[0] = 2;
	if (1 != write(sd, msgbuf, 1)) {
		perror("write"); exit(2);
	}
	if (5 != read(sd, msgbuf+3, 5)) {
		perror("read"); exit(2);
	}
	if (msgbuf[3] != 0x82) {
		fprintf(stderr, "Fatal: invalid response\n");
		exit(2);
	}
	return ntohl(*((int *)(msgbuf+4)));
}

void close_connection(void)
{
	if (sd < 0) {
		fprintf(stderr, "Warning: close_connection w/o connection\n");
		return;
	}
	msgbuf[0] = 3;
	if (1 != write(sd, msgbuf, 1)) {
		perror("write"); exit(2);
	}
	if (1 != read(sd, msgbuf, 1)) {
		perror("read"); exit(2);
	}
	if (msgbuf[0] != 0x83) {
		fprintf(stderr, "Fatal: invalid response\n");
		exit(2);
	}
	close(sd);
	sd = -1;
}
