/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   lzss.c                                             :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: reclaire <reclaire@student.42mulhouse.f    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/05/19 02:27:57 by reclaire          #+#    #+#             */
/*   Updated: 2024/05/24 23:34:35 by reclaire         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft_int.h"
#include <stdlib.h>
#include <stdio.h>

void ft_lzss_compress(U8 *data, U64 len, t_bitstream *stream, U64 window_max_size, U64 lookahead_size)
{
	if (len == 0)
		return;

	U64 window = 0;

	U64 n = 0;
	while (n < len)
	{
		U64 offset = 0;
		U64 size = 0;
		U64 wn = 1;

		while(wn < window + 1)
		{
			U64 i = 0;
			U8 *curr = data - wn;

			//while (i < lookahead_size && (curr + i) < data && *(curr + i) == data[i])	
			while (i < lookahead_size && i + n < len && *(curr + i) == data[i])
				i++;

			if (i > size)
			{
				offset = wn;
				size = i;
			}
			wn++;
		}

		U64 incr = 1;
		if (offset > 0 && size >= 8) // Check nombre de bits
		{
			incr = size;
			ft_bstrm_write_bit(stream, 1);
			ft_bstrm_write_bytes(stream, 4, (U8*)&offset);
			ft_bstrm_write_bytes(stream, 4, (U8*)&size);
#ifdef DEBUG_LZSS
			printf("(ref:%d:%d) ", offset, size);
#endif
		}
		else
		{
#ifdef DEBUG_LZSS
			if (ft_isalnum(*data))
				printf("(lit:%c) ", *data);
			else
				printf("(lit:%d) ", *data);
#endif
			ft_bstrm_write_bit(stream, 0);
			ft_bstrm_write_byte(stream, *data);
		}

		if (window < window_max_size)
			window = MIN(window_max_size, incr + window);
		data += incr;
		n += incr;
	}
}

U64 ft_lzss_decompress(t_bitstream *stream_compressed, U8 *out, U64 len)
{
	U64 out_n = 0;

	//t_bitstream stream = (t_bitstream){.buffer = stream_compressed->buffer, .buffer_max_len = stream_compressed->buffer_max_len, .bits_read = 0, .total_bits_read = 0};
	t_bitstream stream = FT_BITSTREAM_INIT(stream_compressed->buffer, stream_compressed->buffer_max_len);

	while (stream.byte_offset * 8 + stream.bit_offset < stream_compressed->byte_offset * 8 + stream_compressed->bit_offset)
	{
		if (!ft_bstrm_read_bit(&stream))
		{
			//LITTERAL
			U8 b = ft_bstrm_read_byte(&stream);
#ifdef DEBUG_LZSS
			if (ft_isalnum(b))
				printf("(lit:%c n:%lu) ", b, out_n);
			else
				printf("(lit:%d n:%lu) ", b, out_n);
			fflush(stdout);
#endif
			if (out_n >= len)
				return 0;
			out[out_n++] = b;
		}
		else
		{
			//CODE
			U32 offset;
			U32 length;
			ft_bstrm_read_bytes(&stream, 4, (U8*)&offset);
			ft_bstrm_read_bytes(&stream, 4, (U8*)&length);
#ifdef DEBUG_LZSS
			printf("(ref:%d:%d n:%lu) ", offset, length, out_n);
			fflush(stdout);
#endif

			if (out_n + length > len)
				return 0;

			for (U32 n = 0; n < length; n++)
			{
				out[out_n] = *(out + out_n - offset);
				out_n++;
			}
		}
	}
	return out_n;
}
