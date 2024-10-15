/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   address_iterator.h                                 :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: reclaire <reclaire@student.42mulhouse.f    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/10/14 11:07:17 by reclaire          #+#    #+#             */
/*   Updated: 2024/10/15 12:26:56 by reclaire         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#ifndef ADDRESS_ITERATOR_H
#define ADDRESS_ITERATOR_H

#include "libft/std.h"

#define S_SYN 0x1
#define S_NULL 0x2
#define S_FIN 0x4
#define S_XMAS 0x8
#define S_ACK 0x10
#define S_UDP 0x20
#define S_ALL 0x3F

struct s_tcp_hdr
{
	U16 source;
	U16 dest;
	U32 seq;
	U32 ack_seq;
#if __BYTE_ORDER == __LITTLE_ENDIAN
	U16 flags;
#elif __BYTE_ORDER == __BIG_ENDIAN
	U16 doff : 4;
	U16 res1 : 4;
	U16 res2 : 2;
	U16 urg : 1;
	U16 ack : 1;
	U16 psh : 1;
	U16 rst : 1;
	U16 syn : 1;
	U16 fin : 1;
#else
#error "Adjust your <bits/endian.h> defines"
#endif
	U16 window;
	U16 check;
	U16 urg_ptr;
};

enum e_scan_result
{
	R_CLOSED,
	R_FILTERED,
	R_OPEN,
};

typedef struct s_addr_iterator *AddressIterator;
typedef struct s_address
{
	string source_str;
	t_iv3 port;
	bool is_ip;
	union
	{
		struct
		{
			string hostname;
			U32 addr;
		} host;
		t_iv3 ip[4];
	};
} Address;

/*
Returns NULL on failure
Takes care of error messages
*/
AddressIterator address_iterator_init(U16 ports_min, U16 ports_max);

/* No failure */
void address_iterator_destroy(AddressIterator it);

/*
Returns FALSE on failure
Takes care of error messages
*/
bool address_iterator_ingest(AddressIterator it, const_string addr_str);

/*
Returns NULL when no more address
No failure
*/
Address *address_iterator_next(AddressIterator it);

/* No failure */
U64 address_iterator_progress(AddressIterator it);
/* No failure */
U64 address_iterator_total(AddressIterator it);
/* No failure */
U32 address_get_dst_ip(Address *addr);

/*
Returns 0 with `ft_errno != 0` on failure
Takes care of error messages
*/
U32 address_get_src_ip(Address *addr);

#endif
