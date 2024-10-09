# **************************************************************************** #
#                                                                              #
#                                                         :::      ::::::::    #
#    Makefile                                           :+:      :+:    :+:    #
#                                                     +:+ +:+         +:+      #
#    By: reclaire <reclaire@student.42mulhouse.f    +#+  +:+       +#+         #
#                                                 +#+#+#+#+#+   +#+            #
#    Created: 2024/04/15 17:26:47 by reclaire          #+#    #+#              #
#    Updated: 2024/10/09 18:49:30 by reclaire         ###   ########.fr        #
#                                                                              #
# **************************************************************************** #

NAME		=	ft_nmap
include config.mk

INCLUDES	+=	-I./libft -I./ -I./srcs

#CFLAGS		+=	-Wall -Wextra -Werror -O3 -g
#CFLAGS		+=	-g -fsanitize=address
CFLAGS		+=	-g

$(NAME):	_libft objs $(OBJS)
			$(CC) $(INCLUDES) $(LIBS_PATHS) $(OBJS) $(LIBS) -o $(NAME)

_libft:
			$(MAKE) -C ./libft