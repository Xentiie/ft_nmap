/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   t.c                                                :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: reclaire <reclaire@student.42mulhouse.f    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/10/15 11:48:29 by reclaire          #+#    #+#             */
/*   Updated: 2024/10/15 12:22:22 by reclaire         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_nmap.h"


int main()
{
	0x20004;
	struct s_tcp_hdr hdr;
	hdr.source = 4;
	hdr.dest = 2;
	hdr.seq = 1;
	hdr.ack_seq = 1;
	hdr.res1 = 0;
	hdr.doff = 1;
	hdr.fin = 0;
	hdr.syn = 1;
	hdr.rst = 0;
	hdr.psh = 1;
	hdr.ack = 0;
	hdr.urg = 1;
	hdr.res2 = 0;
	hdr.window = 10;
	hdr.check = 11;
	hdr.urg_ptr = 12;
	
	U16 v = 0;
	// v -> v << 4 == res1
	// v << 4 -> v << 8 == doff
	// v << 8 -> v << 9 == fin
	// ...
	// v << 14 -> v << 15 == urg
	// v << 15 -> v << 17 == res2

#if 0
	v |= ((13 & 0xF)); // res1
	v |= ((10 & 0xF) << 4); //doff
	v |= (1 << 8); //fin
	v |= (0 << 9); // syn
	v |= (1 << 10); // rst
	v |= (0 << 11); // psh
	v |= (1 << 12); // ack
	v |= (0 << 13); // urg
	v |= ((2 & 0x3) << 14); // res2
#endif

	v |= 80; //doff
	v |= (1 << 8); //fin
	v |= (0 << 9); // syn
	v |= (0 << 10); // rst
	v |= (1 << 11); // psh
	v |= (0 << 12); // ack
	v |= (1 << 13); // urg
	v |= ((0 & 0x3) << 14); // res2

	printf("	%#x\n", v);

	struct s_tcp_hdr hdr2;
	U8 *addr = &hdr2;
	addr += 12;
	*(U16 *)addr = v;


	printf("%u\n", hdr2.res1);
	printf("%u\n", hdr2.doff);
	printf("%u\n", hdr2.fin);
	printf("%u\n", hdr2.syn);
	printf("%u\n", hdr2.rst);
	printf("%u\n", hdr2.psh);
	printf("%u\n", hdr2.ack);
	printf("%u\n", hdr2.urg);
	printf("%u\n", hdr2.res2);
	
	return 0;
}
