/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   address_iterator.h                                 :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: reclaire <reclaire@student.42mulhouse.f    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/10/14 11:07:17 by reclaire          #+#    #+#             */
/*   Updated: 2024/11/06 12:57:50 by reclaire         ###   ########.fr       */
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

#define R_CLOSED 0x0
#define R_OPEN 0x1
#define R_FILTERED 0x2
#define mk_result(scan_type, result) (((result) & 0x3) << (__builtin_ctz(scan_type) * 2))
#define get_result(scan_type, results) (((results) >> (__builtin_ctz(scan_type) * 2)) & 0x3)

#define range_val(range) (range).x
#define range_min(range) (range).y
#define range_max(range) (range).z

typedef struct s_addr_iterator *AddressIterator;

typedef struct s_address
{
	string source_str;
	t_iv3 port;
	t_iv3 ip[4];
	U32 *results;
} Address;

typedef struct s_scan_addr
{
	Address *addr;
	U32 srcaddr;
	U32 dstaddr;
	U16 port;
} ScanAddress;

U64 address_iterations_cnt(Address *addr);
void address_reset(Address *addr);
bool address_next(Address *addr);
U32 address_get_dst_ip(Address *addr);
U32 address_get_src_ip(Address *addr);

AddressIterator address_iterator_init(U16 ports_min, U16 ports_max);
void address_iterator_destroy(AddressIterator it);
bool address_iterator_ingest(AddressIterator it, const_string addr_str);
void address_iterator_reset(AddressIterator it);
bool address_iterator_next(AddressIterator it, ScanAddress *out);
void address_iterator_set_result(ScanAddress addr, U32 results);
U64 address_iterator_total(AddressIterator it);

#endif
