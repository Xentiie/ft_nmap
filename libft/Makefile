# **************************************************************************** #
#                                                                              #
#                                                         :::      ::::::::    #
#    Makefile                                           :+:      :+:    :+:    #
#                                                     +:+ +:+         +:+      #
#    By: reclaire <reclaire@student.42mulhouse.f    +#+  +:+       +#+         #
#                                                 +#+#+#+#+#+   +#+            #
#    Created: 2022/02/25 09:55:54 by reclaire          #+#    #+#              #
#    Updated: 2024/07/03 05:26:58 by reclaire         ###   ########.fr        #
#                                                                              #
# **************************************************************************** #

NAME		=	libft.so
include config.mk

#CFLAGS		+=	-Wall -Wextra -Werror -O3 -g
CFLAGS		+=	-g -Wall -Wextra
INCLUDES  	+=	-I./ -I./srcs

$(NAME):	$(OBJS)
			$(MKLIB)

test:
	$(CC) -DFT_OS_LINUX -fprofile-generate -fprofile-arcs -ftest-coverage -I./ ./test.c -L./ -lft -o test
