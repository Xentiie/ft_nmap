/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   crypt.h                                            :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: reclaire <reclaire@student.42mulhouse.f    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/05/15 16:46:23 by reclaire          #+#    #+#             */
/*   Updated: 2024/07/02 03:38:30 by reclaire         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#ifndef LIBFT_CRYPT_H
# define LIBFT_CRYPT_H

# include "_libft.h"

U32 ft_crc32(U8 *data, U64 len);
U32 ft_crc32_u(U8 *data, U64 len, U32 crc);

U64 ft_adler32(U8 *data, U64 len, U64 adler);
U32 ft_adler32_end(U64 adler);

#endif