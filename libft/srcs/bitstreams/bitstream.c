/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   bitstream.c                                        :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: reclaire <reclaire@student.42mulhouse.f    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/05/20 23:44:59 by reclaire          #+#    #+#             */
/*   Updated: 2024/05/26 21:56:28 by reclaire         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft_int.h"

#ifdef TEST
# include <stdio.h>
#endif

/*in*/
U8 ft_bstrm_read_bit(t_bitstream *stream)
{
	if (stream->byte_offset > stream->buffer_max_len)
		__FTRETURN_ERR((U8)-1, FT_ERANGE);
	if (stream->bit_offset == 0)
		stream->buffer[stream->byte_offset] = 0;


	U8 out = (stream->buffer[stream->byte_offset] >> stream->bit_offset) & 1;
	stream->bit_offset++;
	if (stream->bit_offset == 8)
	{
		stream->bit_offset = 0;
		stream->byte_offset++;
	}

	__FTRETURN_OK(out);
}

U8 ft_bstrm_read_bits(t_bitstream *stream, U8 n)
{
	if (n > 64)
		__FTRETURN_ERR((U8)-1, FT_ERANGE);
	U8 b = 0;
	for (U8 i = 0; i < n; i++)
	{
		b |= (ft_bstrm_read_bit(stream) << i);
		if (ft_errno != FT_OK)
			__FTRETURN_ERR(-1, ft_errno);
	}
	__FTRETURN_OK(b);
}

U8 ft_bstrm_read_byte(t_bitstream *stream)
{
	U64 n = ft_bstrm_read_bits(stream, 8);
	if (ft_errno != FT_OK)
		__FTRETURN_ERR((U8)-1, ft_errno);
	__FTRETURN_OK((U8)n);
}

void ft_bstrm_read_bytes(t_bitstream *stream, U64 n, U8 *out)
{
	for (U64 i = 0; i < n; i++)
	{
		*out = ft_bstrm_read_byte(stream);
		out++;
		if (ft_errno != FT_OK)
			__FTRETURN_ERR(, ft_errno);
	}
	__FTRETURN_OK();
}

void ft_bstrm_read_align_byte(t_bitstream *stream)
{
	while (stream->bit_offset != 8)
		ft_bstrm_read_bit(stream);
}

U16 ft_bstrm_read_u16_big_endian(t_bitstream *stream)
{
	return (ft_bstrm_read_byte(stream) << 8) | ft_bstrm_read_byte(stream);
}

U16 ft_bstrm_read_u16_little_endian(t_bitstream *stream)
{
	return ft_bstrm_read_byte(stream) | (ft_bstrm_read_byte(stream) << 8);
}

U32 ft_bstrm_read_u32_big_endian(t_bitstream *stream)
{
	return (ft_bstrm_read_byte(stream) << 24) | (ft_bstrm_read_byte(stream) << 16) | (ft_bstrm_read_byte(stream) << 8) | ft_bstrm_read_byte(stream);
}

U32 ft_bstrm_read_u32_little_endian(t_bitstream *stream)
{
	return ft_bstrm_read_byte(stream) | (ft_bstrm_read_byte(stream) << 8) | (ft_bstrm_read_byte(stream) << 16) | (ft_bstrm_read_byte(stream) << 24);
}




/*out*/
void ft_bstrm_write_bit(t_bitstream *stream, U8 bit)
{
	if (stream->byte_offset > stream->buffer_max_len)
		__FTRETURN_ERR(, FT_ERANGE);
	if (stream->bit_offset == 0)
		stream->buffer[stream->byte_offset] = 0;

	stream->buffer[stream->byte_offset] |= ((bit & 1) << stream->bit_offset);
	stream->bit_offset++;
	if (stream->bit_offset == 8)
	{
		stream->bit_offset = 0;
		stream->byte_offset++;
	}

	__FTRETURN_OK();
}

void ft_bstrm_write_bits(t_bitstream *stream, U64 n, U8 *bits)
{
	for (U64 i = 0; i < n; i++)
	{
		ft_bstrm_write_bit(stream, bits[i]);
		if (ft_errno != FT_OK)
			__FTRETURN_ERR(, ft_errno);
	}
	__FTRETURN_OK();
}

void ft_bstrm_write_byte(t_bitstream *stream, U8 byte)
{
	for (U8 i = 0; i < 8; i++)
		ft_bstrm_write_bit(stream, byte >> i);
}

void ft_bstrm_write_bytes(t_bitstream *stream, U64 n, U8 *bytes)
{
	for (U64 i = 0; i < n; i++)
		ft_bstrm_write_byte(stream, bytes[i]);
}

void ft_bstrm_write_0(t_bitstream *stream)
{
	ft_bstrm_write_byte(stream, 0);
}

U64 ft_bstrm_reset_counter(t_bitstream *stream)
{
	U64 out = stream->byte_offset;

	stream->buffer[0] = 0;
	stream->buffer[0] |= stream->buffer[stream->byte_offset];
	stream->byte_offset = 0;
	return out;
}

void ft_bstrm_write_u16_big_endian(t_bitstream *stream, U16 n)
{
	U16 n1 = (n & 0xFF00) >> 8;
	for (U8 i = 0; i < 8; i++)
		ft_bstrm_write_bit(stream, (U8)(n1 >> i));
	for (U8 i = 0; i < 8; i++)
		ft_bstrm_write_bit(stream, (U8)(n >> i));
}


void ft_bstrm_write_u16_little_endian(t_bitstream *stream, U16 n)
{
	for (U8 i = 0; i < 16; i++)
		ft_bstrm_write_bit(stream, n >> i);
}

/*
U32 ft_bstrm_write_u32_big_endian(t_bitstream *stream)
{
	return (ft_bstrm_write_byte(stream) << 24) | (ft_bstrm_write_byte(stream) << 16) | (ft_bstrm_write_byte(stream) << 8) | ft_bstrm_write_byte(stream);
}

U32 ft_bstrm_write_u32_little_endian(t_bitstream *stream)
{
	return ft_bstrm_write_byte(stream) | (ft_bstrm_write_byte(stream) << 8) | (ft_bstrm_write_byte(stream) << 16) | (ft_bstrm_write_byte(stream) << 24);
}
*/


#ifdef TEST

int main()
{
	U8 buffer[100];
	t_bitstream stream = FT_BITSTREAM_INIT(buffer, sizeof(buffer));

	for (int i = 0; i < 100; i++)
	{
		for (int j = 7; j >= 0; j--)
			printf("%d", (i >> j) & 1);
		for (int j = 7; j >= 0; j--)
		{
			printf(" %lu:%lu", stream.byte_offset, stream.bit_offset);
			ft_bstrm_write_bit(&stream, i >> j);
		}
		printf(" %lu  %u\n", stream.bit_offset * 8, buffer[i]);
	}

	printf("\n\n");

	for (int i = 0; i < 100; i++)
		printf("%u\n", buffer[i]);
}

#endif