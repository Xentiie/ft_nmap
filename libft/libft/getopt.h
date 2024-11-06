/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   getopt.h                                           :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: reclaire <reclaire@student.42mulhouse.f    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/02/07 01:30:07 by reclaire          #+#    #+#             */
/*   Updated: 2024/11/06 01:45:57 by reclaire         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#ifndef LIBFT_GETOPT_H
#define LIBFT_GETOPT_H

#include "_libft.h"

extern S32 ft_optopt;
extern S32 ft_optind;
extern S32 ft_opterr;
extern S32 ft_optchr;
extern const_string ft_optarg;

#ifndef no_argument
#define no_argument 0
#endif

#ifndef required_argument
#define required_argument 1
#endif

#ifndef optional_argument
#define optional_argument 2
#endif

typedef struct s_long_opt
{
	string name;
	S32 has_argument; /* can be either `no_argument` (0), `required_argument` (1), or `optional_argument` (2) */
	S32 *flag_ptr;
	S32 flag_value;
} t_long_opt;

S32 ft_getopt(S32 argc, const_string *argv, const_string optstr);
S32 ft_getopt_long(S32 argc, const_string *argv, const_string optstr, const t_long_opt *longopts, S32 *longopts_index);

#endif