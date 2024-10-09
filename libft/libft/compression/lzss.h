/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   lzss.h                                             :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: reclaire <reclaire@student.42mulhouse.f    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/06/02 23:01:54 by reclaire          #+#    #+#             */
/*   Updated: 2024/06/02 23:03:09 by reclaire         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#ifndef LIBFT_LZSS_H
# define LIBFT_LZSS_H

# include "libft/_libft.h"
# include "libft/bitstreams.h"

void ft_lzss_compress(U8 *data, U64 len, t_bitstream *stream, U64 window_max_size, U64 lookahead_size);
U64 ft_lzss_decompress(t_bitstream *stream, U8 *out, U64 len);

#endif