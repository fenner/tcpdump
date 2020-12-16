/*
 * Copyright (c) 2020
 *      Arista Networks, Inc.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   1. Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 *   2. Redistributions in binary form must reproduce the above copyright
 *      notice, this list of conditions and the following disclaimer in
 *      the documentation and/or other materials provided with the
 *      distribution.
 *   3. The names of the authors may not be used to endorse or promote
 *      products derived from this software without specific prior
 *      written permission.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 */

#include <config.h>
#include "netdissect-stdinc.h"
#include <stdlib.h>
#include <string.h>

#include <pcap/pcap.h>
#include "netdissect.h"
#include "print.h"

void
errexit(char *err) {
	fprintf(stderr, "%s", err);
	exit(1);
}

/*
 * We maintain a global buffer for output for the packet, so
 * that we don't output duplicates, only when the output changes.
 */
#define STATIC_BUF_LEN 10000
char outbuf[STATIC_BUF_LEN];
char outbuf2[STATIC_BUF_LEN];
char *buf[2] = { outbuf, outbuf2 };
int curbuf = 0;

char *curpos = outbuf;

void
newbuf() {
    curbuf = 1 - curbuf;
    curpos = buf[curbuf];
}

static int
mysprintf(netdissect_options *ndo, const char *fmt, ...)
{
    va_list args;
    int ret;
    int remaining = STATIC_BUF_LEN - ( curpos - buf[curbuf] );

    va_start(args, fmt);
    ret = vsnprintf(curpos, remaining, fmt, args);
    va_end(args);

    curpos += ret;

    return (ret);
}

int
main( int argc, char **argv ) {
	netdissect_options Ndo;
	netdissect_options *ndo = &Ndo;
	char ebuf[PCAP_ERRBUF_SIZE];
	pcap_t	*p;
	u_int packets_captured = 0;
	int ret;
	struct pcap_pkthdr *hdr;
	const u_char *pkt;

	/*
	 * Initialize the netdissect code.
	 */
	if (nd_init(ebuf, sizeof(ebuf)) == -1)
		errexit(ebuf);

	memset(ndo, 0, sizeof(*ndo));
	ndo_set_function_pointers(ndo);
	ndo->program_name = "trunc-o-matic";
	ndo->ndo_printf = mysprintf;
	/*
	 * TODO: arg parsing
	 * e.g., verbosity
	 * e.g., "-e"
	 */
	ndo->ndo_vflag = 3;
	ndo->ndo_tflag = 1;

	p = pcap_open_offline("input.pcap", ebuf);

	if (p == NULL)
		errexit(ebuf);

	ndo->ndo_if_printer = get_if_printer(pcap_datalink(p));

	ret = pcap_next_ex(p, &hdr, &pkt);
	while (ret > 0) {
	    int caplen;
	    packets_captured++;
	    pretty_print_packet(ndo, hdr, pkt, packets_captured);
	    printf("%s", buf[curbuf]);
	    caplen = hdr->caplen;
	    /* All possible truncation points */
	    while (caplen > 1) {
		hdr->caplen = --caplen;
		newbuf();
		pretty_print_packet(ndo, hdr, pkt, packets_captured);
		if (strcmp(buf[0],buf[1])) {
		    /*
		     * Nicer would be to diff the two bufs and
		     * show just what the difference is
		     */
		    printf("%s", buf[curbuf]);
		}
	    }
	    ret = pcap_next_ex(p, &hdr, &pkt);
	}
	pcap_close(p);
}
