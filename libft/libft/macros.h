/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   macros.h                                           :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: reclaire <reclaire@student.42mulhouse.f    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/11/06 01:46:29 by reclaire          #+#    #+#             */
/*   Updated: 2024/11/06 01:46:30 by reclaire         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#ifndef LIBFT_MACROS_H
# define LIBFT_MACROS_H

# include "_libft.h"

# if defined(__cplusplus)
extern "C" {
# endif

//EXPENSION
#  define	FT_EXP(x) x
//CONCAT
#  define	FT_CONCAT(X, Y) X##Y

//REMOVE PARENTHESIS
#  define FT_DEPAREN(X) __ESC(__ISH X)
#  define __ISH(...) __ISH __VA_ARGS__
#  define __ESC(...) __ESC_(__VA_ARGS__)
#  define __ESC_(...) __VAN ## __VA_ARGS__
#  define __VAN__ISH

#define _REP0(X)
#define _REP1(X) X
#define _REP2(X) _REP1(X) X
#define _REP3(X) _REP2(X) X
#define _REP4(X) _REP3(X) X
#define _REP5(X) _REP4(X) X
#define _REP6(X) _REP5(X) X
#define _REP7(X) _REP6(X) X
#define _REP8(X) _REP7(X) X
#define _REP9(X) _REP8(X) X
#define _REP10(X) _REP9(X) X

/* REPEAT X MULTIPLE TIMES */
#define FT_REP(HUNDREDS,TENS,ONES,X) \
  _REP##HUNDREDS(_REP10(_REP10(X))) \
  _REP##TENS(_REP10(X)) \
  _REP##ONES(X)

/* __VA_ARGS__ UTILS */
/* REMOVE N FIRST ARGS */
#  define FT_VA_ARG_REMOVE_FIRST(N, ...) __FT_VA_ARG_REMOVE_FIRST_##N(__VA_ARGS__)
#  define __FT_VA_ARG_REMOVE_FIRST_1(X, ...) __VA_ARGS__
#  define __FT_VA_ARG_REMOVE_FIRST_2(X, ...) __FT_VA_ARG_REMOVE_FIRST_1(__VA_ARGS__)
#  define __FT_VA_ARG_REMOVE_FIRST_3(X, ...) __FT_VA_ARG_REMOVE_FIRST_2(__VA_ARGS__)
#  define __FT_VA_ARG_REMOVE_FIRST_4(X, ...) __FT_VA_ARG_REMOVE_FIRST_3(__VA_ARGS__)
#  define __FT_VA_ARG_REMOVE_FIRST_5(X, ...) __FT_VA_ARG_REMOVE_FIRST_4(__VA_ARGS__)
#  define __FT_VA_ARG_REMOVE_FIRST_6(X, ...) __FT_VA_ARG_REMOVE_FIRST_5(__VA_ARGS__)
#  define __FT_VA_ARG_REMOVE_FIRST_7(X, ...) __FT_VA_ARG_REMOVE_FIRST_6(__VA_ARGS__)
#  define __FT_VA_ARG_REMOVE_FIRST_8(X, ...) __FT_VA_ARG_REMOVE_FIRST_7(__VA_ARGS__)
#  define __FT_VA_ARG_REMOVE_FIRST_9(X, ...) __FT_VA_ARG_REMOVE_FIRST_8(__VA_ARGS__)
#  define __FT_VA_ARG_REMOVE_FIRST_10(X, ...) __FT_VA_ARG_REMOVE_FIRST_9(__VA_ARGS__)
#  define __FT_VA_ARG_REMOVE_FIRST_11(X, ...) __FT_VA_ARG_REMOVE_FIRST_10(__VA_ARGS__)
#  define __FT_VA_ARG_REMOVE_FIRST_12(X, ...) __FT_VA_ARG_REMOVE_FIRST_11(__VA_ARGS__)
#  define __FT_VA_ARG_REMOVE_FIRST_13(X, ...) __FT_VA_ARG_REMOVE_FIRST_12(__VA_ARGS__)
#  define __FT_VA_ARG_REMOVE_FIRST_14(X, ...) __FT_VA_ARG_REMOVE_FIRST_13(__VA_ARGS__)
#  define __FT_VA_ARG_REMOVE_FIRST_15(X, ...) __FT_VA_ARG_REMOVE_FIRST_14(__VA_ARGS__)
#  define __FT_VA_ARG_REMOVE_FIRST_16(X, ...) __FT_VA_ARG_REMOVE_FIRST_15(__VA_ARGS__)
/* REMOVE N FIRST ARGS */

/* COUNT VA ARG */
#  define FT_VA_ARG_COUNT(...) \
         __FT_VA_ARG_COUNT(__VA_ARGS__,__FT_VA_ARG_COUNT_RSEQ_N())
#  define __FT_VA_ARG_COUNT(...) \
         __FT_VA_ARG_COUNT_N(__VA_ARGS__)
#  define __FT_VA_ARG_COUNT_N( \
          _1, _2, _3, _4, _5, _6, _7, _8, _9,_10, \
         _11,_12,_13,_14,_15,_16,_17,_18,_19,_20, \
         _21,_22,_23,_24,_25,_26,_27,_28,_29,_30, \
         _31,_32,_33,_34,_35,_36,_37,_38,_39,_40, \
         _41,_42,_43,_44,_45,_46,_47,_48,_49,_50, \
         _51,_52,_53,_54,_55,_56,_57,_58,_59,_60, \
         _61,_62,_63,N,...) N
#  define __FT_VA_ARG_COUNT_RSEQ_N() \
         63,62,61,60,                   \
         59,58,57,56,55,54,53,52,51,50, \
         49,48,47,46,45,44,43,42,41,40, \
         39,38,37,36,35,34,33,32,31,30, \
         29,28,27,26,25,24,23,22,21,20, \
         19,18,17,16,15,14,13,12,11,10, \
         9,8,7,6,5,4,3,2,1,0
/* COUNT VA ARG */

/* REVERSE VA ARG */
#  define __reverse_1(a) a
#  define __reverse_2(a, b) b, a
#  define __reverse_3(a, ...) __reverse_2(__VA_ARGS__), a
#  define __reverse_4(a, ...) __reverse_3(__VA_ARGS__), a
#  define __reverse_5(a, ...) __reverse_4(__VA_ARGS__), a
#  define __reverse_6(a, ...) __reverse_5(__VA_ARGS__), a
#  define __reverse_7(a, ...) __reverse_6(__VA_ARGS__), a
#  define __reverse_8(a, ...) __reverse_7(__VA_ARGS__), a
#  define __reverse_9(a, ...) __reverse_8(__VA_ARGS__), a
#  define __reverse_10(a, ...) __reverse_9(__VA_ARGS__), a
#  define __reverse_11(a, ...) __reverse_10(__VA_ARGS__), a
#  define __reverse_12(a, ...) __reverse_11(__VA_ARGS__), a
#  define __reverse_13(a, ...) __reverse_12(__VA_ARGS__), a
#  define __reverse_14(a, ...) __reverse_13(__VA_ARGS__), a
#  define __reverse_15(a, ...) __reverse_14(__VA_ARGS__), a
#  define __reverse_16(a, ...) __reverse_15(__VA_ARGS__), a
#  define __reverse1(N, ...) __reverse_##N(__VA_ARGS__)
#  define FT_MACRO_REVERSE(N, ...) __reverse1(N, __VA_ARGS__)
/* REVERSE VA ARG */


#  define FT_EXPAND(...) __VA_ARGS__
#  define FT_POP(X, ...) __VA_ARGS__
#  define FT_PUSH(X, ...) X, __VA_ARGS__
#  define FT_APPEND(X, ...) __VA_ARGS__, X
#  define FT_TOP(X, ...) X
#  define FT_VOID(...)
/* __VA_ARGS__ UTILS */

//https://www.scs.stanford.edu/~dm/blog/va-opt.html

/* VA ARG FOREACH */
#   define __parens ()
#   define __expand(...) __expand_4(__expand_4(__expand_4(__expand_4(__VA_ARGS__))))
#   define __expand_4(...) __expand_3(__expand_3(__expand_3(__expand_3(__VA_ARGS__))))
#   define __expand_3(...) __expand_2(__expand_2(__expand_2(__expand_2(__VA_ARGS__))))
#   define __expand_2(...) __expand_1(__expand_1(__expand_1(__expand_1(__VA_ARGS__))))
#   define __expand_1(...) __VA_ARGS__
#   define FT_MACRO_FOR_EACH(macro, ...) __VA_OPT__(__expand(__for_each_helper(macro, __VA_ARGS__)))
#   define __for_each_helper(macro, a1, ...)	\
	macro(a1)									\
		__VA_OPT__(, __for_each_again __parens(macro, __VA_ARGS__))
#   define __for_each_again() __for_each_helper
/* VA ARG FOREACH */

/* VA ARG FOREACH BUT WITH sep BETWEEN EACH macro(x) -> FT_MACRO_FOR_EACH_sep(FT_EXP, %, a, b, c) -> a % b % c */
#   define FT_MACRO_FOR_EACH_sep(macro, sep, ...) __VA_OPT__(__expand(__for_each_sep_helper(macro, sep, __VA_ARGS__)))
#   define __for_each_sep_helper(macro, sep, a1, ...)	\
	macro(a1)								\
		__VA_OPT__(sep __for_each_sep_again __parens(macro, sep, __VA_ARGS__))
#   define __for_each_sep_again() __for_each_sep_helper

#   define FT_MACRO_FOR_EACH_sep_arg(macro, sep, arg, ...) __VA_OPT__(__expand(__for_each_sep_arg_helper(macro, sep, arg, __VA_ARGS__)))
#   define __for_each_sep_arg_helper(macro, sep, arg, a1, ...)	\
	macro(FT_DEPAREN(arg), a1)								\
		__VA_OPT__(sep __for_each_sep_arg_again __parens(macro, sep, arg, __VA_ARGS__))
#   define __for_each_sep_arg_again() __for_each_sep_arg_helper
/* VA ARG FOREACH BUT WITH sep BETWEEN EACH macro(x) -> FT_MACRO_FOR_EACH_sep(FT_EXP, %, a, b, c) -> a % b % c */

/* VA ARG FOREACH 2 (for nested FOREACH)*/
#   define __parens2 ()
#   define __expand2(...) __expand2_4(__expand2_4(__expand2_4(__expand2_4(__VA_ARGS__))))
#   define __expand2_4(...) __expand2_3(__expand2_3(__expand2_3(__expand2_3(__VA_ARGS__))))
#   define __expand2_3(...) __expand2_2(__expand2_2(__expand2_2(__expand2_2(__VA_ARGS__))))
#   define __expand2_2(...) __expand2_1(__expand2_1(__expand2_1(__expand2_1(__VA_ARGS__))))
#   define __expand2_1(...) __VA_ARGS__
#   define FT_MACRO_FOR_EACH2(macro, ...) __VA_OPT__(__expand2(__for_each_helper2(macro, __VA_ARGS__)))
#   define __for_each_helper2(macro, a1, ...)	\
	macro(a1)									\
		__VA_OPT__(, __for_each_again2 __parens2(macro, __VA_ARGS__))
#   define __for_each_again2() __for_each_helper2
/* VA ARG FOREACH 2 (for nested FOREACH)*/

/* VA ARG FOREACH WITH macro_args PASSED TO macro*/
#   define __parens3 ()
#   define __expand3(...) __expand3_4(__expand3_4(__expand3_4(__expand3_4(__VA_ARGS__))))
#   define __expand3_4(...) __expand3_3(__expand3_3(__expand3_3(__expand3_3(__VA_ARGS__))))
#   define __expand3_3(...) __expand3_2(__expand3_2(__expand3_2(__expand3_2(__VA_ARGS__))))
#   define __expand3_2(...) __expand3_1(__expand3_1(__expand3_1(__expand3_1(__VA_ARGS__))))
#   define __expand3_1(...) __VA_ARGS__
#   define FT_MACRO_FOR_EACH_arg(macro, macro_args, ...) __VA_OPT__(__expand3(__for_each_helper_arg(macro, macro_args, __VA_ARGS__)))
#   define __for_each_helper_arg(macro, macro_args, a1, ...)	\
	macro(FT_DEPAREN(macro_args), a1)								\
		__VA_OPT__(, __for_each_again_arg __parens3(macro, macro_args, __VA_ARGS__))
#   define __for_each_again_arg() __for_each_helper_arg
/* VA ARG FOREACH WITH macro_args PASSED TO macro*/

/* VA ARG FOREACH WITH macro_args PASSED TO macro 2 (for nested FOREACH_arg)*/
#   define __parens4 ()
#   define __expand4(...) __expand4_4(__expand4_4(__expand4_4(__expand4_4(__VA_ARGS__))))
#   define __expand4_4(...) __expand4_3(__expand4_3(__expand4_3(__expand4_3(__VA_ARGS__))))
#   define __expand4_3(...) __expand4_2(__expand4_2(__expand4_2(__expand4_2(__VA_ARGS__))))
#   define __expand4_2(...) __expand4_1(__expand4_1(__expand4_1(__expand4_1(__VA_ARGS__))))
#   define __expand4_1(...) __VA_ARGS__
#   define FT_MACRO_FOR_EACH_arg2(macro, macro_args, ...) __VA_OPT__(__expand4(__for_each_helper_arg2(macro, macro_args, __VA_ARGS__)))
#   define __for_each_helper_arg2(macro, macro_args, a1, ...)	\
	macro(FT_DEPAREN(macro_args), a1)								\
		__VA_OPT__(, __for_each_again_arg2 __parens4(macro, macro_args, __VA_ARGS__))
#   define __for_each_again_arg2() __for_each_helper_arg2
/* VA ARG FOREACH WITH macro_args PASSED TO macro 2 (for nested FOREACH_arg)*/


/* OVERLOAD */
#   define FT_MACRO_GROUP_TYPE(...) void (*)(__VA_ARGS__)
#   define FT_MACRO_GROUP_TYPE_INST(...) (void (*)(FT_MACRO_FOR_EACH(typeof, __VA_ARGS__)))0

#   define __flparens ()
#   define __flexpand(...) __flexpand_4(__flexpand_4(__flexpand_4(__flexpand_4(__VA_ARGS__))))
#   define __flexpand_4(...) __flexpand_3(__flexpand_3(__flexpand_3(__flexpand_3(__VA_ARGS__))))
#   define __flexpand_3(...) __flexpand_2(__flexpand_2(__flexpand_2(__flexpand_2(__VA_ARGS__))))
#   define __flexpand_2(...) __flexpand_1(__flexpand_1(__flexpand_1(__flexpand_1(__VA_ARGS__))))
#   define __flexpand_1(...) __VA_ARGS__
#   define fix_list(...) __VA_OPT__(__flexpand(__fl_helper(__VA_ARGS__)))
#   define __fl_nempty(...) __VA_OPT__(__VA_ARGS__)
#   define __fl_helper(a1, ...) __fl_nempty(a1)	 __VA_OPT__(, __fl_again __flparens(__VA_ARGS__))
#   define __fl_again() __fl_helper


#   define DO_COMBS(M, MA, ...) __VA_OPT__(fix_list(__expand(__do_combs_helper(M, MA, (), __VA_ARGS__))))

#   define first_arg(opt) FT_TOP opt
#   define rm_first_arg(opt) (FT_POP opt)

#   define _next_opt(M, MA, lst, ...) __VA_OPT__(__do_combs_again __parens(M, MA, lst, __VA_ARGS__))
#   define __all_opt(M, MA, lst, opt, todo, ...) __VA_OPT__(__do_combs_again __parens(M, MA, lst, opt, FT_DEPAREN(todo)))
#   define _all_opt(M, MA, lst, opt, ...) __all_opt(M, MA, lst, opt, (__VA_ARGS__), FT_DEPAREN(opt))

#   define comma_if_not_empty(...) __VA_OPT__(__VA_ARGS__,)

#   define generate(M, MA, lst) FT_EXPAND(M(MA, lst)),
#   define try_generate(M, MA, lst, opt, ...) FT_DEPAREN(__VA_OPT__(FT_VOID)(generate(M, MA, (comma_if_not_empty(FT_DEPAREN(lst)) first_arg(opt)))))


#   define __do_combs_helper(M, MA, lst, opt, ...)	\
	try_generate(M, MA, lst, opt, __VA_ARGS__) \
	_next_opt(M, MA, (comma_if_not_empty(FT_DEPAREN(lst)) first_arg(opt)), __VA_ARGS__) \
	_all_opt(M, MA, lst, rm_first_arg(opt), __VA_ARGS__)

#   define __do_combs_again() __do_combs_helper

#   define build(f, X) FT_MACRO_GROUP_TYPE(FT_DEPAREN(X)): f
#   define do_one(f, ...) DO_COMBS(build, f, __VA_ARGS__)
#   define parse_args(X) do_one X


#   define OVERLOAD(args, ...)								\
	_Generic(FT_MACRO_GROUP_TYPE_INST args,				\
		FT_MACRO_FOR_EACH2(parse_args, __VA_ARGS__)		\
	)args
/* OVERLOAD */
/*
The most cursed C macro in existence to this day.

Provides full C function.
Usage:

#define my_c_overloaded_function(...) OVERLOAD((__VA_ARGS__)	\
	(my_c_overloaded_function1, (char*)),						\
	(my_c_overloaded_function1, (char*, void*)),				\
	(my_c_overloaded_function1, (float, double, int)),			\
)

*/


# if defined(__cplusplus)
}
# endif

#endif