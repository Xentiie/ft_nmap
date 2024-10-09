/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   _os.h                                              :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: reclaire <reclaire@student.42mulhouse.f    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/08/28 16:16:11 by reclaire          #+#    #+#             */
/*   Updated: 2024/09/25 06:02:26 by reclaire         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#ifndef FT__OS_H
#define FT__OS_H

# if defined(FT_OS_UNKNOWN) || (!defined(FT_OS_WIN) && !defined(FT_APPLE) && !defined(FT_OS_LINUX))

#  if defined(WIN32) || defined(_WIN32) || defined(__WIN32__) || defined(__NT__)
#   define FT_OS_WIN
#   define WIN32_LEAN_AND_MEAN 
#   ifdef _WIN64
#    define FT_OS_WIN64 
#   else
#    define FT_OS_WIN32
#   endif

#  elif __APPLE__
#   define FT_APPLE
#   include <TargetConditionals.h>
#   if TARGET_IPHONE_SIMULATOR
#    define FT_APPLE_SIM
#   elif TARGET_OS_MACCATALYST
#    define FT_APPLE_MACCATALYST
#   elif TARGET_OS_IPHONE
#    define FT_APPLE_IOS
#   elif TARGET_OS_MAC
#    define FT_APPLE_OSX
#   else
#    error "Unknown Apple platform"
#   endif

#  elif __ANDROID__
#   define FT_ANDROID
#  elif __linux__
#   define FT_OS_LINUX
#  elif __unix__
#   define FT_UNIX
#  elif defined(_POSIX_VERSION)
#   define FT_POSIX
#  else
#   error "Unknown compiler"
#  endif

# endif

#define FT_TARGET_WIN ((S32)(1 << 0))
#define FT_TARGET_APPLE ((S32)(1 << 1))
#define FT_TARGET_LINUX ((S32)(1 << 2))


#endif