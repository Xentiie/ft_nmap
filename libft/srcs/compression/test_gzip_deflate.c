/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   test_gzip_deflate.c                                :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: reclaire <reclaire@student.42mulhouse.f    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/06/19 15:15:36 by reclaire          #+#    #+#             */
/*   Updated: 2024/07/01 23:51:11 by reclaire         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft/std.h"

#ifdef TEST_GZIP_DEFLATE
#include "libft/compression/deflate.h"
#include "libft/compression/gzip.h"
#include "libft/io.h"
#include "libft/std.h"
#include "libft/ansi.h"
#include <stdio.h>
#include <stdlib.h>

int decompress_deflate(const unsigned char *compressed_data, size_t compressed_size, unsigned char *output_buffer, size_t output_buffer_size) {
    z_stream stream;
    int ret;

    // Initialize the zlib stream structure
    ft_memset(&stream, 0, sizeof(stream));
    stream.next_in = (unsigned char *)compressed_data;
    stream.avail_in = compressed_size;

    // Initialize the inflate state
    ret = inflateInit2(&stream, -MAX_WBITS);
    if (ret != Z_OK) {
        return ret;
    }

    // Decompress loop
    do {
        stream.next_out = output_buffer;
        stream.avail_out = output_buffer_size;

        ret = inflate(&stream, Z_NO_FLUSH);
        switch (ret) {
            case Z_STREAM_END:
                inflateEnd(&stream);
                return Z_OK;
            case Z_OK:
            case Z_BUF_ERROR:
                // Check if we have consumed all input data
                if (stream.avail_in == 0) {
                    inflateEnd(&stream);
                    return Z_OK;
                }
                break;
            default:
                inflateEnd(&stream);
                return ret;
        }
    } while (ret != Z_STREAM_END);

    // Clean up and return
    inflateEnd(&stream);
    return Z_OK;
}


U64 compress_data(U8 *data_out, U64 out_size, U32 *crc)
{
	U8 buff_in[2048];
	U64 in_size;

	{
		file fd = ft_fopen("./test_gzip_deflate_old.c", "r");
		in_size = ft_fread(fd, (char *)buff_in, sizeof(buff_in));
	}

	t_deflate_stream deflate_stream = {0};
	deflate_stream.in = buff_in;
	deflate_stream.in_size = in_size;
	deflate_stream.out = data_out;
	deflate_stream.out_size = out_size;
	ft_deflate_next_block(&deflate_stream, 4096, 1, 1);

	*crc = deflate_stream.crc32;

	{
		U8 buff[1024];
		t_gzip_header header = {0};
		header.os = FT_GZIP_OS_UNIX;
		U64 header_size = ft_gzip_write_header(buff, sizeof(buff), &header);

		file fd = ft_fopen("./test2.gz", "w+");
		ft_fwrite(fd, (char *)buff, header_size);
		ft_fwrite(fd, (char *)data_out, deflate_stream.out_used);

		ft_gzip_write_footer(buff, deflate_stream.crc32, deflate_stream.in_used);
		ft_fwrite(fd, (char *)buff, 8);

		ft_fclose(fd);
	}
	
	return deflate_stream.out_used;
}

int main2()
{
	U8 buff_in[10000] = {0};
	U32 crc32;
	U64 in_size = compress_data(buff_in, sizeof(buff_in), &crc32);
	(void)in_size;
	U8 buff_out[10000] = {0};

	printf("\n\n");

	//U8 tmp[10000];
	//decompress_deflate(buff_in, in_size, tmp, sizeof(tmp));

	printf("\n\n");
	t_deflate_stream stream = {0};
	ft_inflate_init(&stream);

	stream.in = buff_in;
	stream.in_size = 1000;
	stream.out = buff_out;
	stream.out_size = 1000;

	U64 in_used = 0;
	U64 out_used = 0;

	while (1)
	{
		S32 ret = ft_inflate(&stream);
		if (ret == FT_INFLATE_RET_NOT_DONE)
		{
			out_used += stream.out_used;
			stream.out += stream.out_used;
			stream.out_used = 0;

			in_used += stream.in_used;
			stream.in += stream.in_used;
			stream.in_used = 0;
		}
		if (ret < 0)
		{
			printf("inflate error: %d\n", ret);
			break;
		}
		if (ret == FT_INFLATE_RET_DONE)
		{
			in_used += stream.in_used;
			out_used += stream.out_used;
			printf("inflate done\n");
			break;
		}
		printf(FT_GREEN"INFLATE RETURNED\n"FT_CRESET);
	}

	printf("IN USED: %lu\n", in_used);
	printf("OUT USED: %lu\n", out_used);
	printf("%.*s\n", (int)out_used, buff_out);

	printf("\ncrc32 deflate: %#x\n", crc32);
	printf("crc32 inflate: %#x\n", 1);
}

int main()
{
//	printf("%d\n", ((15*288) * 4) //ll code lengths
//	+ ((15*32) * 4) // dist code lengths
//	+ ((19*32) * 4)); // cl code length
//	return 0;

	U8 buff_in[10000] = {0};
	U64 in_size = 0;

	{
		file fd = ft_fopen("./tmp.gz", "r");
		while (in_size < sizeof(buff_in))
		{
			S64 _rd = ft_fread(fd, buff_in + in_size, sizeof(buff_in));
			if (_rd <= 0)
				break;
			in_size += _rd;
		}
		ft_fclose(fd);
	}

	U8 buff_out[15000] = {0};


	//U8 tmp[10000];
	//decompress_deflate(buff_in, in_size, tmp, sizeof(tmp));

	t_gzip_header header = {0};
	U64 header_size = ft_gzip_read_header(buff_in, in_size, &header, FT_GZIP_READ_FLAG_IGNORE_FILENAME);

	t_deflate_stream stream = {0};
	ft_inflate_init(&stream);

	stream.in = buff_in + header_size;
	stream.in_size = in_size;
	stream.out = buff_out;
	stream.out_size = sizeof(buff_out);

	U64 in_used = 0;
	U64 out_used = 0;

	while (1)
	{
		S32 ret = ft_inflate(&stream);

			in_used += stream.in_used;
			out_used += stream.out_used;



		if (ret == FT_INFLATE_RET_NOT_DONE)
		{
			out_used += stream.out_used;
			stream.out += stream.out_used;
			stream.out_used = 0;

			in_used += stream.in_used;
			stream.in += stream.in_used;
			stream.in_used = 0;
		}
		if (ret < 0)
		{
			printf("inflate error: %d\n", ret);
			break;
		}
		if (ret == FT_INFLATE_RET_DONE)
		{
			in_used += stream.in_used;
			out_used += stream.out_used;
			printf("inflate done\n");
			break;
		}
		//printf(FT_GREEN"INFLATE RETURNED\n"FT_CRESET);
	}

	ft_inflate_end(&stream);

	U32 file_crc;
	U32 file_size;
	ft_gzip_read_footer(buff_in + in_used + header_size, &file_crc, &file_size);

	printf("%.*s\n", (int)out_used, buff_out);
	printf("IN USED: %lu\n", in_used);
	printf("OUT USED: %lu\n", out_used);

	printf("\nfile size: %u\n", file_size);
	printf("inflate size: %u\n", stream.out_used);

	printf("\ncrc32 deflate: %#x\n", file_crc);
	printf("crc32 inflate: %#x\n", stream.crc32);
}

#endif