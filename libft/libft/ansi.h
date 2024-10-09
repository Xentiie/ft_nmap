/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ansi.h                                             :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: reclaire <reclaire@student.42mulhouse.f    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/02/11 19:53:23 by reclaire          #+#    #+#             */
/*   Updated: 2024/09/25 18:00:21 by reclaire         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#ifndef LIBFT_ANSI_H
# define LIBFT_ANSI_H

# include "_libft.h"

# define FT_BLACK					"\e[0;30m"
# define FT_RED						"\e[0;31m"
# define FT_GREEN					"\e[0;32m"
# define FT_YELLOW					"\e[0;33m"
# define FT_BLUE					"\e[0;34m"
# define FT_MAGENTA					"\e[0;35m"
# define FT_CYAN					"\e[0;36m"
# define FT_WHITE					"\e[0;37m"
# define FT_DEFAULT					"\e[0;39m"

# define FT_LBLACK					"\e[0;90m"
# define FT_LRED					"\e[0;91m"
# define FT_LGREEN					"\e[0;92m"
# define FT_LYELLOW					"\e[0;93m"
# define FT_LBLUE					"\e[0;94m"
# define FT_LMAGENTA				"\e[0;95m"
# define FT_LCYAN					"\e[0;96m"
# define FT_LWHITE					"\e[0;97m"
# define FT_LDEFAULT				"\e[0;99m"

# define FT_BG_BLACK				"\e[0;40m"
# define FT_BG_RED					"\e[0;41m"
# define FT_BG_GREEN				"\e[0;42m"
# define FT_BG_YELLOW				"\e[0;43m"
# define FT_BG_BLUE					"\e[0;44m"
# define FT_BG_MAGENTA				"\e[0;45m"
# define FT_BG_CYAN					"\e[0;46m"
# define FT_BG_WHITE				"\e[0;47m"
# define FT_BG_DEFAULT				"\e[0;49m"

# define FT_BG_LBLACK				"\e[0;100m"
# define FT_BG_LRED					"\e[0;101m"
# define FT_BG_LGREEN				"\e[0;102m"
# define FT_BG_LYELLOW				"\e[0;103m"
# define FT_BG_LBLUE				"\e[0;104m"
# define FT_BG_LMAGENTA				"\e[0;105m"
# define FT_BG_LCYAN				"\e[0;106m"
# define FT_BG_LWHITE				"\e[0;107m"
# define FT_BG_LDEFAULT				"\e[0;109m"

# define FT_BOLD					"\e[1m"
# define FT_DIM						"\e[2m"
# define FT_ITALIC					"\e[3m"
# define FT_UNDERLINE				"\e[4m"
# define FT_BLINK					"\e[5m"
# define FT_BLINK_FAST				"\e[6m"
# define FT_INVERSE					"\e[7m"
# define FT_INVISIBLE				"\e[8m"
# define FT_STRIKETHROUGH			"\e[9m"
# define FT_FONT1					"\e[10m"
# define FT_FONT2					"\e[11m"
# define FT_FONT3					"\e[12m"
# define FT_FONT4					"\e[13m"
# define FT_FONT5					"\e[14m"
# define FT_FONT6					"\e[15m"
# define FT_FONT7					"\e[16m"
# define FT_FONT8					"\e[17m"
# define FT_FONT9					"\e[18m"
# define FT_FONT10					"\e[19m"
# define FT_GOTHIC					"\e[20m"
# define FT_UNDERLINE2				"\e[21m"
# define FT_NO_INTENSITY			"\e[22m"
# define FT_NO_ITALIC				"\e[23m"
# define FT_NO_UNDERLINE			"\e[24m"
# define FT_NO_BLINKING				"\e[25m"
# define FT_NOTHING					"\e[26m"
# define FT_NO_REVERSE				"\e[27m"
# define FT_REVEAL					"\e[28m"
# define FT_NO_STRIKE				"\e[29m"
# define FT_FOREGROUND_COLOR(r,g,b)	"\e[38;2;"#r";"#g";"#b"m"
# define FT_NO_FOREGROUND			"\e[39m"
# define FT_BACKGROUND_COLOR(r,g,b)	"\e[48;2;"#r";"#g";"#b"m"
# define FT_NO_BACKGROUND			"\e[49m"
# define FT_FRAMED					"\e[51m"
# define FT_ENCIRCLED				"\e[52m"
# define FT_OVERLINED				"\e[53m"
# define FT_NO_FRAMED_ENCIRCLED		"\e[54m"
# define FT_NO_OVERLINED			"\e[55m"
# define FT_UNDERLINE_COLOR(r,g,b) 	"\e[58;2;"r";"g";"b"m"
# define FT_NO_UNDERLINE_COLOR		"\e[59m"

# define FT_CURSOR_UP(n)			"\e["#n"A"
# define FT_CURSOR_DOWN(n)			"\e["#n"B"
# define FT_CURSOR_FORWARD(n)		"\e["#n"C"
# define FT_CURSOR_BACK(n)			"\e["#n"D"

//Reset
# define FT_CRESET					"\e[0m"

#endif