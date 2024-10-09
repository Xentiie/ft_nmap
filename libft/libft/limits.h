/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   limits.h                                           :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: reclaire <reclaire@student.42mulhouse.f    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/02/11 19:55:11 by reclaire          #+#    #+#             */
/*   Updated: 2024/02/23 20:45:24 by reclaire         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#ifndef LIBFT_LIMITS_H
# define LIBFT_LIMITS_H

# include "_libft.h"

# define U8_MAX  255
# define U8_MIN  0
# define U16_MAX 65535
# define U16_MIN 0
# define U32_MAX 4294967295
# define U32_MIN 0
# define U64_MAX 18446744073709551615UL
# define U64_MIN 0UL
# define S8_MAX  127
# define S8_MIN  -128
# define S16_MAX 32767
# define S16_MIN -32768
# define S32_MAX 2147483647
# define S32_MIN -2147483648
# define S64_MAX 9223372036854775807
# define S64_MIN -9223372036854775807
# define F32_MAX 3.40282346638528859811704183484516925e+38F
# define F32_MIN 1.17549435082228750796873653722224568e-38F
# define F64_MAX ((double)1.79769313486231570814527423731704357e+308L)
# define F64_MIN ((double)2.22507385850720138309023271733240406e-308L)

# define U8_MAX_MAG		3
# define U16_MAX_MAG	5
# define U32_MAX_MAG	10
# define U64_MAX_MAG	20

# define S8_MAX_MAG		3
# define S16_MAX_MAG	5
# define S32_MAX_MAG	10
# define S64_MAX_MAG	19

#endif