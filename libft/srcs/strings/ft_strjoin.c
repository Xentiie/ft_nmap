/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_strjoin.c                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: reclaire <reclaire@student.42mulhouse.f    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2022/02/23 15:42:29 by reclaire          #+#    #+#             */
/*   Updated: 2024/09/03 03:19:39 by reclaire         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft_int.h"
#include <stdarg.h>

string	ft_strjoin(const_string s1, const_string s2)
{
	string	str;

	str = malloc((ft_strlen(s1) + ft_strlen(s2) + 1) * sizeof(char));
	if (str == NULL)
		__FTRETURN_ERR(NULL, FT_EOMEM);
	str[0] = '\0';
	ft_strcat(str, s1);
	ft_strcat(str, s2);

	__FTRETURN_OK(str);
}
