/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_nmap.h                                          :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: reclaire <reclaire@student.42mulhouse.f    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/10/09 16:31:46 by reclaire          #+#    #+#             */
/*   Updated: 2024/10/10 04:31:52 by reclaire         ###   ########.fr       */
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

#ifndef __USE_MISC
#define __USE_MISC 1
#endif

#include <ifaddrs.h>
#include <arpa/inet.h>
#define __USE_XOPEN2K 1
#include <netdb.h>
#include <netinet/ip_icmp.h>

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

enum e_scan_type
{
	S_NONE = -1,
	S_SYN,
	S_NULL,
	S_FIN,
	S_XMAS,
	S_ACK,
	S_UDP
};

/* parameters */
extern U16 ports_min, ports_max;   /* range of ports to scan */
extern U8 thread_count;			   /* number of threads */
extern enum e_scan_type scan_type; /* scan type */

/* variables */
extern U32 srcaddr;		  /* source address */
extern U32 *dstaddr;	  /* destination addresses, as a 32 bit unsigned integer */
extern U32 dstaddr_cnt;	  /* destination addresses count */
extern U32 dstaddr_alloc; /* destination addresses buffer allocation size */

extern const const_string scan_types_str[7]; /* scan types names */
#define get_scan_type() (scan_types_str[scan_type + 1])


/* address iterator */
typedef struct s_addr_iterator *AddressIterator;
typedef struct s_addr
{
	U32 addr;
	U16 port;
	string address_name;
} Address;

AddressIterator address_iterator_init();
void address_iterator_destroy(AddressIterator it);
bool address_iterator_ingest(AddressIterator it, const_string addr_str);
bool address_iterator_next(AddressIterator it, Address *addr);

U16 checksum(U16 *ptr, U64 nbytes);
string addr_to_str(U32 addr);
// Returns NULL on error
string full_addr_to_str(U32 addr);
// Returns 0 on error
U32 dns_resolve(const_string addr);

#endif