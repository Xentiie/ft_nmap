/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   inflate.c                                          :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: reclaire <reclaire@student.42mulhouse.f    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/05/30 11:07:21 by reclaire          #+#    #+#             */
/*   Updated: 2024/08/06 04:31:03 by reclaire         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft_int.h"
#include "fixed_codes.h"
#include "deflate_int.h"
#include <stdlib.h>

//#define DEBUG

#ifdef DEBUG
#include <stdio.h>
#define IFDEBUG(...) \
	do               \
	{                \
		__VA_ARGS__; \
	} while (0);
#else
#define IFDEBUG(...)
#endif

const U8 cl_code_length_encoding_i[] = {16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15};

// clang-format off
enum e_inf_state {
	INV = -1,
	BLK_HEAD,
		RD_UNCOMPRESS,
			UNCOMPRESS_CPY,

		N_LL_CODES,
		N_DIST_CODES,
		N_CL_CODES,
		CL_CODES,
		RD_CL_CODE,
		LEN_CODES,

		RD_CODE,

		LIT,

		RD_EXTRA_LEN,
		RD_DIST,
		RD_EXTRA_DIST,

		CPY_BACKREF
};
// clang-format on

S32 ft_inflate_fast(t_deflate_stream *stream);

/* Load registers with state in inflate() for speed */
#define LOAD()                                             \
	do                                                     \
	{                                                      \
		if (UNLIKELY(stream->in_used > stream->in_size))   \
			return FT_INFLATE_RET_INVALID_IN_SIZE;         \
		if (UNLIKELY(stream->out_used > stream->out_used)) \
			return FT_INFLATE_RET_INVALID_OUT_SIZE;        \
		have = stream->in_size - stream->in_used;          \
		left = stream->out_size - stream->out_used;        \
		next = stream->in + stream->in_used;               \
		hold = inf_data->hold;                             \
		bits = stream->bits;                               \
		code = inf_data->code;                             \
	} while (0)

/* Restore stream from registers in inflate() */
#define RESTORE()                                                      \
	do                                                                 \
	{                                                                  \
		stream->in_used += (stream->in_size - stream->in_used) - have; \
		inf_data->hold = hold;                                         \
		stream->bits = bits;                                           \
		inf_data->code = code;                                         \
	} while (0)

/* Clear the input bit accumulator */
#define INITBITS() \
	do             \
	{              \
		hold = 0;  \
		bits = 0;  \
	} while (0)

/* Get a byte of input into the bit accumulator, or return from inflate()
   if there is no input available. */
#define PULLBYTE()                                \
	do                                            \
	{                                             \
		if (have == 0)                            \
		{                                         \
			ret = FT_INFLATE_RET_NOT_DONE;        \
			goto inflate_leave;                   \
		}                                         \
		have--;                                   \
		hold += (unsigned long)(*next++) << bits; \
		bits += 8;                                \
	} while (0)

/* Assure that there are at least n bits in the bit accumulator.  If there is
   not enough available input to do that, then return from inflate(). */
#define NEEDBITS(n)                  \
	do                               \
	{                                \
		while (bits < (unsigned)(n)) \
			PULLBYTE();              \
	} while (0)

/* Return the low n bits of the bit accumulator (n < 16) */
#define BITS(n) \
	((unsigned)hold & ((1U << (n)) - 1))

/* Remove n bits from the bit accumulator */
#define DROPBITS(n)            \
	do                         \
	{                          \
		hold >>= (n);          \
		bits -= (unsigned)(n); \
	} while (0)

/* Remove zero to seven bits as needed to go to a byte boundary */
#define BYTEBITS()         \
	do                     \
	{                      \
		hold >>= bits & 7; \
		bits -= bits & 7;  \
	} while (0)

enum code_length_type
{
	CL,
	LL,
	DIST,
};

#define MOD_ADLER 65521

U32 adler32(const U8 *data, size_t len)
{
	U32 a = 1, b = 0;

	while (len > 0)
	{
		size_t tlen = len > 5552 ? 5552 : len;
		len -= tlen;
		do
		{
			a += *data++;
			b += a;
		} while (--tlen);

		a %= MOD_ADLER;
		b %= MOD_ADLER;
	}

	return (b << 16) | a;
}

static bool code_length_to_code_table(U16 *code_lengths, U64 code_lengths_len, struct s_code *code_table_out, U16 max_code_length, enum code_length_type type)
{
	U16 *next_code = a_malloc(sizeof(U16) * max_code_length + sizeof(U8) * max_code_length);
	if (next_code == NULL)
		return FALSE;
	ft_bzero(next_code, sizeof(U16) * max_code_length + sizeof(U8) * max_code_length);

	U8 *lengths_count = ((U8 *)next_code) + sizeof(U16) * max_code_length;
	for (U64 i = 0; i < code_lengths_len; i++)
		lengths_count[code_lengths[i]]++;

	U32 code = 0;
	lengths_count[0] = 0;
	for (U8 bits = 1; bits < (max_code_length + 1); bits++)
	{
		code = (code + lengths_count[bits - 1]) << 1;
		next_code[bits] = code;
	}

	IFDEBUG(if (type == CL) printf("	CL codes:\n"); else if (type == LL) printf("	LL codes:\n"); else printf("	Dist codes:\n");)

	for (U64 i = 0; i < code_lengths_len; i++)
	{
		U16 length = code_lengths[i];
		if (length != 0)
		{
			IFDEBUG(
				printf("		%lu: ", i);
				for (U16 j = 0; j < length; j++)
					printf("%d", (next_code[length] >> (length - j - 1)) & 1);
				printf("\n"))

			U8 op;
			U16 val;
			switch (type)
			{
			case CL:
				op = 0;
				val = i;
				break;
			case LL:
				if (i <= 255)
					op = 0x80;
				else if (i == 256)
					op = 0x20;
				else
					op = 0x40 | ll_table[i - 257].extra_bits;

				if (i <= 256)
					val = i;
				else
					val = ll_table[i - 257].min;
				break;
			case DIST:
				op = 0x40 | offset_table[i].extra_bits;
				val = offset_table[i].min;
				break;
			}

			U16 n1 = next_code[length];
			U16 n = 0;
			for (U8 j = 0; j < length; j++)
				n |= ((n1 >> j) & 0x1) << (length - j - 1);

			for (U64 j = 0; j <= ((1U << max_code_length) - 1) >> (length); j++)
				code_table_out[n | (j << length)] = (struct s_code){.nbits = length, .val = val, .op = op};
			next_code[length]++;
		}
	}
	a_free(next_code);

	return TRUE;
}

FUNCTION_HOT S32 ft_inflate(t_deflate_stream *stream)
{
	U64 hold;		// bit accumulator
	U64 have, left; // remaining in, remaining out
	U8 bits;		// bit counter
	U8 *next;
	U16 to_cpy;
	S32 ret; // return value on quit
	U64 out_st;
	struct s_code code;
	struct s_inflate_data *inf_data = stream->inflate;

	LOAD();
	out_st = stream->out_used;

	while (TRUE)
	{
		switch (inf_data->state)
		{
		case BLK_HEAD:
			IFDEBUG(printf("Reading block:\n"))
			NEEDBITS(3);

			inf_data->last = BITS(1);
			IFDEBUG(printf("	last: %s\n", inf_data->last ? "yes" : "no"))

			DROPBITS(1);
			switch (BITS(2))
			{
			case 0:
				IFDEBUG(printf("	block type: uncompressed\n"))
				inf_data->state = RD_UNCOMPRESS;
				break;

			case 1:
				IFDEBUG(printf("	block type: fixed\n"))
				inf_data->ll_codes = (struct s_code *)fixed_ll_codes;
				inf_data->dist_codes = (struct s_code *)fixed_dist_codes;
				inf_data->ll_codes_bits = 9;
				inf_data->dist_codes_bits = 5;
				inf_data->state = RD_CODE;
				break;

			case 2:
				IFDEBUG(printf("	block type: dynamic\n"))
				inf_data->state = N_LL_CODES;
				break;

			case 3:
				IFDEBUG(printf("	block type: INVALID\n"))
				DROPBITS(2);
				inf_data->state = INV;
				ret = FT_INFLATE_RET_ERROR;
				goto inflate_leave;
			}
			DROPBITS(2);
			break;

		case RD_UNCOMPRESS:
			BYTEBITS();
			NEEDBITS(32);

			if ((hold & 0xFFFF) != ((hold >> 16) ^ 0xFFFF))
			{
				IFDEBUG(printf("	invalid size/~size\n"))
				inf_data->state = INV;
				ret = FT_INFLATE_RET_ERROR;
				goto inflate_leave;
			}
			inf_data->length = hold & 0xFFFF;
			IFDEBUG(printf("	size: %u\n", inf_data->length))
			inf_data->state = UNCOMPRESS_CPY;
			/* fallthrough */

		case UNCOMPRESS_CPY:;
			to_cpy = inf_data->length;
			if (to_cpy)
			{
				if (to_cpy > have)
					to_cpy = have;
				if (to_cpy > left)
					to_cpy = left;
				if (to_cpy == 0)
				{
					ret = FT_INFLATE_RET_NOT_DONE;
					goto inflate_leave;
				}
				IFDEBUG(printf("	copying %u bytes\n", to_cpy))
				ft_memcpy(stream->out + stream->out_used, next, to_cpy);

				have -= to_cpy;
				left -= to_cpy;
				inf_data->length -= to_cpy;

				next += to_cpy;
				stream->out_used += to_cpy;
				inf_data->window_size += to_cpy;
				break;
			}
			inf_data->state = BLK_HEAD;
			break;

		case N_LL_CODES:
			NEEDBITS(5);
			inf_data->n_ll_codes = BITS(5) + 257;
			DROPBITS(5);
			IFDEBUG(printf("	Num ll codes: %u\n", inf_data->n_ll_codes))
			inf_data->state = N_DIST_CODES;
			/* fallthrough */

		case N_DIST_CODES:
			NEEDBITS(5);
			inf_data->n_dist_codes = BITS(5) + 1;
			DROPBITS(5);
			IFDEBUG(printf("	Num dist codes: %u\n", inf_data->n_dist_codes))
			inf_data->state = N_CL_CODES;
			/* fallthrough */

		case N_CL_CODES:
			NEEDBITS(4);
			inf_data->n_cl_codes = BITS(4) + 4;
			DROPBITS(4);
			IFDEBUG(printf("	Num CL codes: %u\n", inf_data->n_cl_codes))
			inf_data->have = 0;
			inf_data->state = CL_CODES;
			/* fallthrough */

		case CL_CODES:
			while (inf_data->have < inf_data->n_cl_codes)
			{
				NEEDBITS(3);
				inf_data->cl_code_length[cl_code_length_encoding_i[inf_data->have++]] = (U16)BITS(3);
				DROPBITS(3);
			}
			while (inf_data->have < 19)
				inf_data->cl_code_length[cl_code_length_encoding_i[inf_data->have++]] = 0;
			IFDEBUG(
				printf("	CL code lengths (0 - 18):");
				for (U8 i = 0; i < 19; i++)
					printf(" %u", inf_data->cl_code_length[i]);
				printf("\n");)

			inf_data->max_code_length = 0;
			for (U64 i = 0; i < 19; i++)
				inf_data->max_code_length = MAX(inf_data->max_code_length, inf_data->cl_code_length[i]);

			inf_data->cl_codes = malloc(sizeof(struct s_code) * ((1U << (inf_data->max_code_length + 1)) - 1));
			if (inf_data->cl_codes == NULL)
			{
				ret = FT_INFLATE_RET_OMEM;
				inf_data->state = INV;
				goto inflate_leave;
			}
			ft_memset(inf_data->cl_codes, 1, sizeof(inf_data->cl_codes));
			if (!code_length_to_code_table(inf_data->cl_code_length, 19, inf_data->cl_codes, inf_data->max_code_length, CL))
			{
				ret = FT_INFLATE_RET_OMEM;
				inf_data->state = INV;
				goto inflate_leave;
			}

			inf_data->have = 0;
			inf_data->last_symbol = -1;
			inf_data->state = RD_CL_CODE;
			/* fallthrough */

		case RD_CL_CODE:
			while (TRUE)
			{
				code = inf_data->cl_codes[BITS(inf_data->max_code_length)];
				if (code.nbits <= bits)
					break;
				PULLBYTE();
			}
			DROPBITS(code.nbits);
			inf_data->state = LEN_CODES;
			/* fallthrough */

		case LEN_CODES:
			switch (code.val)
			{
			case 16:;
				NEEDBITS(2);

				IFDEBUG(printf("	Symbol 16 (repeat count: %u)\n", BITS(2) + 3))

				for (U8 i = 0; i < BITS(2) + 3; i++)
				{
					if (inf_data->have >= inf_data->n_ll_codes)
						inf_data->dist_code_length[inf_data->have - inf_data->n_ll_codes] = inf_data->last_symbol;
					else
						inf_data->ll_code_length[inf_data->have] = inf_data->last_symbol;
					inf_data->have++;
				}
				DROPBITS(2);
				break;
			case 17:;
				NEEDBITS(3);

				IFDEBUG(printf("	Symbol 17 (repeat count: %u)\n", BITS(3) + 3))

				for (U8 i = 0; i < BITS(3) + 3; i++)
				{
					if (inf_data->have >= inf_data->n_ll_codes)
						inf_data->dist_code_length[inf_data->have - inf_data->n_ll_codes] = 0;
					else
						inf_data->ll_code_length[inf_data->have] = 0;
					inf_data->have++;
				}
				inf_data->last_symbol = 0;
				DROPBITS(3);
				break;
			case 18:;
				NEEDBITS(7);

				IFDEBUG(printf("	Symbol 18 (repeat count: %u)\n", BITS(7) + 11))

				for (U8 i = 0; i < BITS(7) + 11; i++)
				{
					if (inf_data->have >= inf_data->n_ll_codes)
						inf_data->dist_code_length[inf_data->have - inf_data->n_ll_codes] = 0;
					else
						inf_data->ll_code_length[inf_data->have] = 0;
					inf_data->have++;
				}
				inf_data->last_symbol = 0;
				DROPBITS(7);
				break;
			default:

				// IFDEBUG(printf("	Symbol %u (%u)\n", code.val, code.nbits))

				if (inf_data->have >= inf_data->n_ll_codes)
					inf_data->dist_code_length[inf_data->have - inf_data->n_ll_codes] = code.val;
				else
					inf_data->ll_code_length[inf_data->have] = code.val;
				inf_data->have++;
				inf_data->last_symbol = code.val;
				break;
			}

			if (inf_data->have < inf_data->n_ll_codes + inf_data->n_dist_codes)
			{
				inf_data->state = RD_CL_CODE;
				break;
			}

			free(inf_data->cl_codes);

			{
				inf_data->ll_codes_bits = 0;
				for (U16 i = 0; i < 288; i++)
					inf_data->ll_codes_bits = MAX(inf_data->ll_codes_bits, inf_data->ll_code_length[i]);

				inf_data->ll_codes = malloc(sizeof(struct s_code) * ((1U << (inf_data->ll_codes_bits + 1)) - 1));
				if (inf_data->ll_codes == NULL)
				{
					ret = FT_INFLATE_RET_OMEM;
					inf_data->state = INV;
					goto inflate_leave;
				}
				ft_memset(inf_data->ll_codes, 1, sizeof(inf_data->ll_codes));
				if (!code_length_to_code_table(inf_data->ll_code_length, inf_data->n_ll_codes, inf_data->ll_codes, inf_data->ll_codes_bits, LL))
				{
					ret = FT_INFLATE_RET_OMEM;
					inf_data->state = INV;
					goto inflate_leave;
				}
			}

			{
				inf_data->dist_codes_bits = 0;
				for (U16 i = 0; i < 32; i++)
					inf_data->dist_codes_bits = MAX(inf_data->dist_codes_bits, inf_data->dist_code_length[i]);

				inf_data->dist_codes = malloc(sizeof(struct s_code) * ((1U << (inf_data->dist_codes_bits + 1)) - 1));
				if (inf_data->dist_codes == NULL)
				{
					ret = FT_INFLATE_RET_OMEM;
					inf_data->state = INV;
					goto inflate_leave;
				}
				ft_memset(inf_data->dist_codes, 0, sizeof(inf_data->dist_codes));
				if (!code_length_to_code_table(inf_data->dist_code_length, inf_data->n_dist_codes, inf_data->dist_codes, inf_data->dist_codes_bits, DIST))
				{
					ret = FT_INFLATE_RET_OMEM;
					inf_data->state = INV;
					goto inflate_leave;
				}
			}

			inf_data->state = RD_CODE;

			/* fallthrough */

		case RD_CODE:

			//if (have >= 8 && left >= 258)
			//{
			//	RESTORE();
			//	ft_inflate_fast(stream);
			//	LOAD();
			//	break;
			//}

			while (TRUE)
			{
				code = inf_data->ll_codes[BITS(inf_data->ll_codes_bits)];
				if (code.nbits <= bits)
					break;
				PULLBYTE();
			}

			switch (code.op >> 4)
			{
			case 0x80 >> 4:
				// Literal
				inf_data->state = LIT;
				break;
			case 0x40 >> 4:
				// Backref
				IFDEBUG(printf("	Backref:\n		code:%#x(%u)\n		base length: %u\n", BITS(code.nbits), code.nbits, code.val))
				inf_data->length = code.val;
				inf_data->state = RD_EXTRA_LEN;
				break;
			case 0x20 >> 4:
				// Code 256
				IFDEBUG(printf("	End of block marker found\n"))
				inf_data->state = BLK_HEAD;
				break;
			default:
				IFDEBUG(printf("	Error: invalid code\n"))
				inf_data->state = INV;
				ret = FT_INFLATE_RET_ERROR;
				DROPBITS(code.nbits);
				goto inflate_leave;
			}
			DROPBITS(code.nbits);
			break;

		case RD_EXTRA_LEN:
			NEEDBITS(code.op & 0xF);
			IFDEBUG(printf("		extra length: %u\n", BITS(code.op & 0xF)));
			inf_data->length += BITS(code.op & 0xF);
			DROPBITS(code.op & 0xF);
			inf_data->state = RD_DIST;
			/* fallthrough */

		case RD_DIST:

			while (TRUE)
			{
				code = inf_data->dist_codes[BITS(inf_data->dist_codes_bits)];
				if (code.nbits <= bits)
					break;
				PULLBYTE();
			}
			IFDEBUG(printf("		code:%#x(%u)\n", BITS(code.nbits), code.nbits))
			DROPBITS(code.nbits);
			inf_data->dist = code.val;
			IFDEBUG(printf("		base dist: %u\n", inf_data->dist))
			inf_data->state = RD_EXTRA_DIST;
			/* fallthrough */

		case RD_EXTRA_DIST:
			NEEDBITS(code.op & 0xF);
			inf_data->dist += BITS(code.op & 0xF);
			IFDEBUG(printf("		extra dist: %u\n", inf_data->dist))
			DROPBITS(code.op & 0xF);

			IFDEBUG(printf("		FULL: %u:%u\n", inf_data->length, inf_data->dist))
			inf_data->state = CPY_BACKREF;
			/* fallthrough */

		case CPY_BACKREF:
			if (inf_data->dist > inf_data->window_size)
			{
				IFDEBUG(printf("	INVALID BACKREF: too far back\n"))
				inf_data->state = INV;
				ret = FT_INFLATE_RET_ERROR;
				goto inflate_leave;
			}
			if (inf_data->length == 0)
			{
				inf_data->state = RD_CODE;
				break;
			}

			to_cpy = inf_data->length;

			IFDEBUG(printf("	Copying backref:\n"));
			IFDEBUG(printf("		to copy: %u\n", to_cpy));

			U8 *start_cpy = inf_data->win_next - inf_data->dist;
			IFDEBUG(printf("		window start offset: %ld\n", (S64)(start_cpy - inf_data->window)));
			if (start_cpy < inf_data->window)
			{
				start_cpy += FT_DEFLATE_WINDOW_SIZE;
				IFDEBUG(printf("	start is under window, going around to: %ld\n", (S64)(start_cpy - inf_data->window)))
			}

			to_cpy = MIN(to_cpy, left);
			// IFDEBUG(printf("		MIN(left): %u\n", to_cpy));
			to_cpy = MIN(to_cpy, FT_DEFLATE_WINDOW_SIZE - (start_cpy - inf_data->window));
			// IFDEBUG(printf("		MIN(FT_DEFLATE_WINDOW_SIZE - (start_cpy - inf_data->window)): %u\n", to_cpy));
			to_cpy = MIN(to_cpy, FT_DEFLATE_WINDOW_SIZE - (inf_data->win_next - inf_data->window) + 1);
			// IFDEBUG(printf("		MIN(FT_DEFLATE_WINDOW_SIZE - (inf_data->win_next - inf_data->window)): %u\n", to_cpy));
			IFDEBUG(printf("		final to copy: %u\n", to_cpy));
			if (to_cpy == 0)
			{
				ret = FT_INFLATE_RET_NOT_DONE;
				goto inflate_leave;
			}

			for (U64 i = 0; i < to_cpy; i++)
			{
				*(stream->out + stream->out_used++) = *start_cpy;
				*inf_data->win_next++ = *start_cpy++;
			}

			inf_data->length -= to_cpy;
			left -= to_cpy;
			inf_data->window_size += to_cpy;

			if (inf_data->win_next >= inf_data->window + FT_DEFLATE_WINDOW_SIZE)
				inf_data->win_next = inf_data->window;

			break;

		case LIT:
			if (left == 0)
			{
				ret = FT_INFLATE_RET_NOT_DONE;
				goto inflate_leave;
			}

			if (inf_data->win_next - inf_data->window >= FT_DEFLATE_WINDOW_SIZE)
				inf_data->win_next = inf_data->window;

			*inf_data->win_next++ = (U8)code.val;
			inf_data->window_size++;

			*(stream->out + stream->out_used) = (U8)code.val;
			stream->out_used++;
			left--;

			IFDEBUG(
				if (ft_isprint(code.val))
					printf("	lit: %c\n", code.val);
				else printf("	lit: %#x\n", code.val);)
			inf_data->state = RD_CODE;
			break;

		case INV:
			ret = FT_INFLATE_RET_ERROR;
			goto inflate_leave;
		}

		if (inf_data->state == BLK_HEAD && inf_data->last)
		{
			ret = FT_INFLATE_RET_DONE;
			goto inflate_leave;
		}
	}

inflate_leave:

	if (ret >= 0)
	{
		U64 len = stream->out_used - out_st;
		stream->crc32 = ft_crc32_u(stream->out + out_st, len, stream->crc32);

		for (U64 i = 0; i < len; i++)
		{
			stream->adler_a = (stream->adler_a + (stream->out + out_st)[i]) % MOD_ADLER;
			stream->adler_b = (stream->adler_b + stream->adler_a) % MOD_ADLER;
		}
	}

	RESTORE();
	return ret;
}

U32 ft_inflate_addler32(t_deflate_stream *stream)
{
	return (stream->adler_b << 16) | stream->adler_a;
}

bool ft_inflate_init(t_deflate_stream *stream)
{
	ft_memset(stream, 0, sizeof(t_deflate_stream));
	stream->inflate = malloc(sizeof(struct s_inflate_data));
	if (UNLIKELY(stream->inflate == NULL))
		return FALSE;
	ft_memset(stream->inflate, 0, sizeof(struct s_inflate_data));

	stream->inflate->window = malloc(sizeof(U8) * FT_DEFLATE_WINDOW_SIZE);
	if (UNLIKELY(stream->inflate->window == NULL))
		return FALSE;
	stream->inflate->window_size = 0;
	stream->inflate->win_next = stream->inflate->window;

	stream->inflate->hold = 0;

	stream->adler_a = 1;
	stream->adler_b = 0;

	return TRUE;
}

void ft_inflate_end(t_deflate_stream *stream)
{
	free(stream->inflate->window);
	if (stream->inflate->ll_codes != fixed_ll_codes)
		free(stream->inflate->ll_codes);
	if (stream->inflate->dist_codes != fixed_dist_codes)
		free(stream->inflate->dist_codes);
	free(stream->inflate);
}

S32 ft_inflate_fast(t_deflate_stream *stream)
{
	struct s_inflate_data *inf_data = stream->inflate;

	struct s_code code;
	U16 length;
	U16 dist;

	U64 val = inf_data->hold;
	do
	{
		while (stream->bits < 48)
		{
			val += ((U64)stream->in[stream->in_used] << stream->bits);
			stream->bits += 8;
			stream->in_used++;
		}

		code = inf_data->ll_codes[val & ((1U << inf_data->ll_codes_bits) - 1)];
		val >>= code.nbits;
		stream->bits -= code.nbits;

		switch (code.op >> 4)
		{
		case 0x80 >> 4:
			// Literal
			if (UNLIKELY(inf_data->win_next - inf_data->window >= FT_DEFLATE_WINDOW_SIZE))
				inf_data->win_next = inf_data->window;

			*inf_data->win_next++ = (U8)code.val;
			inf_data->window_size++;

			*(stream->out + stream->out_used) = (U8)code.val;
			stream->out_used++;

			IFDEBUG(
				if (ft_isprint(code.val))
					printf("[fast]	lit: %c\n", code.val);
				else printf("[fast]	lit: %#x\n", code.val);)
			break;
		case 0x40 >> 4:
			// Backref
			length = code.val;
			IFDEBUG(printf("[fast]	Backref:\n		code:???(%u)\n		base length: %u\n", code.nbits, code.val))
			length += val & ((1U << (code.op & 0xF)) - 1);
			IFDEBUG(printf("[fast]		extra length: %lu\n", val & ((1U << (code.op & 0xF)) - 1)));
			val >>= (code.op & 0xF);
			stream->bits -= (code.op & 0xF);

			code = inf_data->dist_codes[val & ((1U << inf_data->dist_codes_bits) - 1)];
			IFDEBUG(printf("[fast]		code:%#lx(%u)\n", val & ((1U << inf_data->ll_codes_bits) - 1), code.nbits));
			val >>= code.nbits;
			stream->bits -= code.nbits;
			dist = code.val;
			IFDEBUG(printf("[fast]		base dist: %u\n", code.val))
			dist += val & ((1U << (code.op & 0xF)) - 1);
			IFDEBUG(printf("[fast]		extra dist: %lu\n", val & ((1U << (code.op & 0xF)) - 1)));
			val >>= (code.op & 0xF);
			stream->bits -= (code.op & 0xF);
			IFDEBUG(printf("[fast]		FULL: %u:%u\n", length, dist))

			if (UNLIKELY(inf_data->dist > inf_data->window_size))
			{
				IFDEBUG(printf("[fast]	INVALID BACKREF: too far back\n"))
				stream->inflate->state = INV;
				return -1;
			}

			do
			{
				U16 to_cpy = length;

				IFDEBUG(printf("[fast]	Copying backref:\n"));
				IFDEBUG(printf("[fast]		to copy: %u\n", to_cpy));

				U8 *start_cpy = inf_data->win_next - dist;
				IFDEBUG(printf("[fast]		window start offset: %ld\n", (S64)(start_cpy - inf_data->window)));
				if (UNLIKELY(start_cpy < inf_data->window))
				{
					start_cpy += FT_DEFLATE_WINDOW_SIZE;
					IFDEBUG(printf("[fast]	start is under window, going around to: %ld\n", (S64)(start_cpy - inf_data->window)))
				}

				to_cpy = MIN(to_cpy, stream->out_size - stream->out_used);
				to_cpy = MIN(to_cpy, FT_DEFLATE_WINDOW_SIZE - (start_cpy - inf_data->window));
				to_cpy = MIN(to_cpy, FT_DEFLATE_WINDOW_SIZE - (inf_data->win_next - inf_data->window) + 1);
				IFDEBUG(printf("[fast]		final to copy: %u\n", to_cpy));
				if (UNLIKELY(to_cpy == 0))
				{
					stream->inflate->state = INV;
					return -1;
				}

				for (U64 i = 0; i < to_cpy; i++)
				{
					*(stream->out + stream->out_used + i) = *start_cpy;
					*inf_data->win_next++ = *start_cpy++;
				}

				length -= to_cpy;
				stream->out_used += to_cpy;
				inf_data->window_size += to_cpy;

				if (UNLIKELY(inf_data->win_next >= inf_data->window + FT_DEFLATE_WINDOW_SIZE))
					inf_data->win_next = inf_data->window;
			} while (length);

			break;
		case 0x20 >> 4:
			// Code 256
			IFDEBUG(printf("[fast]	End of block marker found\n"))
			inf_data->state = BLK_HEAD;
			inf_data->hold = val;
			return 1;
		default:
			IFDEBUG(printf("[fast]	Error: invalid code\n"))
			stream->inflate->state = INV;
			return -1;
		}

	} while (stream->in_size - stream->in_used >= 8 && stream->out_size - stream->out_used >= 258);

	
	return 0;
}
