/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   bitstreams.h                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: reclaire <reclaire@student.42mulhouse.f    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/05/20 23:45:18 by reclaire          #+#    #+#             */
/*   Updated: 2024/05/26 21:56:28 by reclaire         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#ifndef LIBFT_BITSTREAMS_H
#define LIBFT_BITSTREAMS_H

typedef struct s_bitstream
{
	U8 *buffer;
	U64 buffer_max_len;

	U8 bit_offset;
	U64 byte_offset;
} t_bitstream;

#define FT_BITSTREAM_INIT(buf, max_len) ((t_bitstream){.buffer = buf, .buffer_max_len = max_len, .bit_offset = 0, .byte_offset = 0})

U8 ft_bstrm_read_bit(t_bitstream *stream);
U8 ft_bstrm_read_bits(t_bitstream *stream, U8 n);
U8 ft_bstrm_read_byte(t_bitstream *stream);
void ft_bstrm_read_bytes(t_bitstream *stream, U64 n, U8 *out);
void ft_bstrm_read_align_byte(t_bitstream *stream);
U16 ft_bstrm_read_u16_big_endian(t_bitstream *stream);
U16 ft_bstrm_read_u16_little_endian(t_bitstream *stream);
U32 ft_bstrm_read_u32_big_endian(t_bitstream *stream);
U32 ft_bstrm_read_u32_little_endian(t_bitstream *stream);

void ft_bstrm_write_bit(t_bitstream *stream, U8 bit);
void ft_bstrm_write_bits(t_bitstream *stream, U64 n, U8 *bits);
void ft_bstrm_write_byte(t_bitstream *stream, U8 byte);
void ft_bstrm_write_bytes(t_bitstream *stream, U64 n, U8 *bytes);
//Appends a 0 byte at the end of the stream, to byte-align it
void ft_bstrm_write_0(t_bitstream *stream);
//Returns the number of bytes written in the stream, and sets internal counter to 0 bytes (keeps current written bits that needs to be filled)
U64 ft_bstrm_reset_counter(t_bitstream *stream);

void ft_bstrm_write_u16_big_endian(t_bitstream *stream, U16 n);
void ft_bstrm_write_u16_little_endian(t_bitstream *stream, U16 n);

#endif