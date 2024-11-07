/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_nmap.h                                          :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: reclaire <reclaire@student.42mulhouse.f    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/10/09 16:31:46 by reclaire          #+#    #+#             */
/*   Updated: 2024/11/07 15:58:42 by reclaire         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#ifndef FT_NMAP_H
#define FT_NMAP_H

#include "libft/std.h"
#include "libft/time.h"
#include "libft/getopt.h"
#include "libft/io.h"
#include "libft/limits.h"
#include "libft/strings.h"
#include "libft/maths.h"

#include "address_iterator.h"

#define array_len(x) (sizeof(x) / sizeof((x)[0]))

struct s_ip_hdr
{
#if __BYTE_ORDER == __LITTLE_ENDIAN
	U8 ihl : 4; // Internet header length
	U8 ver : 4; // 4:IPv4 6:IPv6
#else
#warning "???"
	U8 ver : 4; // 4:IPv4 6:IPv6
	U8 ihl : 4; // Header length
#endif
	U8 tos;		  // Deprecated. 0
	U16 len;	  // Total packet length
	U16 id;		  // Identification
	U16 flgs_frg; // Flags / frag off
	U8 ttl;
	U8 protocol;
	U16 check; // Header checksum
	U32 src_addr;
	U32 dst_addr;
	/* opts */
};

struct s_tcp_hdr
{
	U16 source;
	U16 dest;
	U32 seq;
	U32 ack_seq;
	U16 flags;
	U16 window;
	U16 check;
	U16 urg_ptr;
};

struct s_tcp_pseudo_hdr
{
	U32 source_address;
	U32 dest_address;
	U8 placeholder;
	U8 protocol;
	U16 tcp_length;
	struct s_tcp_hdr tcp_hdr;
};

struct s_udp_hdr
{
	U16 srcaddr;
	U16 dstaddr;
	U16 len;
	U16 check;
};

struct s_icmp_hdr
{
	U8 type;
	U8 code;
	U16 checksum;

	union
	{
		struct
		{
			U16 id;
			U16 seq;
		};

		struct
		{
			U32 unused;
		} dest_unreachable;

		struct
		{
			U32 unused;
		} time_exceeded;

		struct
		{
			U32 ptr; // >> 24
		} param_problem;

		struct
		{
			U32 unused;
		} src_quench;

		struct
		{
			U32 gateway_addr;
		} redirect;

		struct
		{
			U16 id;
			U16 seq;
		} echo;

		struct
		{
			U16 id;
			U16 seq;
		} echo_reply;

		struct
		{
			U16 id;
			U16 seq;
			U32 src_timestamp;
			U32 rcv_timestamp;
			U32 transmit_timestamp;
		} timestamp;

		struct
		{
			U16 id;
			U16 seq;
			U32 src_timestamp;
			U32 rcv_timestamp;
			U32 transmit_timestamp;
		} timestamp_reply;
	} req;
};

/* parameters */
extern bool g_has_capnetraw;		/* has CAPNETRAW set, for raw sockets without root */
extern U8 g_scans;					/* scan type */
extern U32 g_srcaddr;				/* custom source address */
extern bool g_use_custom_interface; /* custom interface specified, use g_srcaddr as source address */
extern U8 g_ttl;					/* ttl value */
extern t_time g_timeout;			/* timeout value */

/* threads */
void *run_scans(AddressIterator it);

/* utils */
U16 checksum(U16 *ptr, U64 nbytes);

/* PAS THREAD SAFE */
string addr_to_str(U32 addr);
/* THREAD SAFE */
string addr_to_str2(U32 addr, char *buf, U64 size);

/*
Returns NULL on failure
Takes care of error messages
*/
string full_addr_to_str(U32 addr);

void scan_to_str(U8 type, char buffer[], U64 size);
/* return 0 on failure */
U8 str_to_scan(const_string str);

#endif