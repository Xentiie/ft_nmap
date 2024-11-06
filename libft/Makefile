# **************************************************************************** #
#                                                                              #
#                                                         :::      ::::::::    #
#    Makefile                                           :+:      :+:    :+:    #
#                                                     +:+ +:+         +:+      #
#    By: reclaire <reclaire@student.42mulhouse.f    +#+  +:+       +#+         #
#                                                 +#+#+#+#+#+   +#+            #
#    Created: 2022/02/25 09:55:54 by reclaire          #+#    #+#              #
#    Updated: 2024/10/23 19:07:28 by reclaire         ###   ########.fr        #
#                                                                              #
# **************************************************************************** #

include config.mk

$(NAME): $(OBJS)
	ar -rcs libft.a $(OBJS)

test:
	$(CC) -DFT_OS_LINUX -fprofile-generate -fprofile-arcs -ftest-coverage -I./ ./test.c -L./ -lft -o test