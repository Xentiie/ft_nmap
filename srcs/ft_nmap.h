/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_nmap.h                                          :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: reclaire <reclaire@student.42mulhouse.f    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/10/09 16:31:46 by reclaire          #+#    #+#             */
/*   Updated: 2024/10/15 16:17:35 by reclaire         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#ifndef FT_NMAP_H
#define FT_NMAP_H

#include "libft/std.h"
#include "libft/getopt.h"
#include "libft/io.h"
#include "libft/limits.h"
#include "libft/strings.h"
#include "libft/maths.h"

#include "address_iterator.h"

#define array_len(x) (sizeof(x) / sizeof((x)[0]))

typedef struct s_ip_header
{
#if __BYTE_ORDER == __LITTLE_ENDIAN
	U8 ihl : 4; // Internet header length
	U8 ver : 4; // 4:IPv4 6:IPv6
#else
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
} t_ip_header;

/* return NULL on failure */
void scan_to_str(U8 type, char buffer[], U64 size);
/* return -1 on failure */
U8 str_to_scan(const_string str);

/* parameters */
extern U8 scan_type;			  /* scan type */
extern bool use_custom_interface; /* custom interface specified, use _srcaddr as source address */
extern U32 _srcaddr;

/* threads */
typedef struct s_thread_param
{
	AddressIterator it;
	filedesc sock;
} t_thread_param;
void *run_test(t_thread_param *it);

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

/*
Returns 0 with `ft_errno != 0` on failure
Takes care of error messages
*/
U32 dns_resolve(const_string addr);

#endif