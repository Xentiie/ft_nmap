/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_nmap.h                                          :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: reclaire <reclaire@student.42mulhouse.f    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/10/09 16:31:46 by reclaire          #+#    #+#             */
/*   Updated: 2024/10/22 16:26:09 by reclaire         ###   ########.fr       */
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

/* parameters */
extern bool g_has_capnetraw;
extern U8 g_scans;					/* scan type */
extern bool g_use_custom_interface; /* custom interface specified, use g_srcaddr as source address */
extern U32 g_srcaddr;
extern t_time g_timeout;

/* threads */
void *run_test(AddressIterator it);

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