/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   main.c                                             :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: reclaire <reclaire@student.42mulhouse.f    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/10/09 15:50:03 by reclaire          #+#    #+#             */
/*   Updated: 2024/10/23 17:45:46 by reclaire         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_nmap.h"
#include "libft/time.h"
#include "libft/socket.h"
#include "libft/ansi.h"

#ifndef __USE_MISC
#define __USE_MISC 1
#endif

#include <stdlib.h>
#include <stdio.h>
#include <regex.h>
#include <pthread.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/ioctl.h>

#include <ifaddrs.h>
#include <arpa/inet.h>
#define __USE_XOPEN2K 1
#include <netdb.h>
#include <netinet/ip_icmp.h>

bool g_has_capnetraw;
U8 g_scans;
bool g_use_custom_interface;
U32 g_srcaddr;
t_time g_timeout;

void *run_test_udp(AddressIterator it);

static const t_long_opt long_opts[] = {
	{"file", TRUE, NULL, 'f'},
	{"help", FALSE, NULL, 'h'},
	{"ip", TRUE, NULL, 'i'},
	{"interface", TRUE, NULL, 'I'},
	{"ports", TRUE, NULL, 'p'},
	{"speedup", TRUE, NULL, 's'},
	{"scan", TRUE, NULL, 'S'},
	{"timeout", TRUE, NULL, 't'},
	{0},
};

static void print_help();

int main()
{
	U8 thread_count;		   /* number of threads */
	U16 ports_min, ports_max;  /* default port min/max */
	const_string dstaddr_file; /* file containing target addresses. NULL if no file has been specified */
	const_string ip_arg;	   /* additional ip address specified by --ip */
	F32 timeout_flt;		   /* socket timeout */
	pthread_t *threads;		   /* list of all threads */

	char buf[30] = {0}; /* pour scan_to_str */
	t_iv2 term_size;	/* terminal size */
	AddressIterator it;
	S64 i, j;

	{
		filedesc tmpsock;

		g_has_capnetraw = TRUE;
		if ((tmpsock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)) == -1)
		{ /* test root access */
			uid_t uid;

			if ((uid = setuid(0)) != 0)
			{
				ft_fprintf(ft_fstderr, "%s: should be run with CAP_NET_RAW or root privileges\n", ft_argv[0]);
				return 1;
			}
			(void)setuid(uid);
			g_has_capnetraw = FALSE;
		}
		else
			ft_close(tmpsock);
	}

	{
		struct winsize w;
		ioctl(0, TIOCGWINSZ, &w);
		term_size.x = w.ws_col;
		term_size.y = w.ws_row;
		(void)term_size;
	}

	{
		const string range_reg_src = "^\\[([0-9]+)-([0-9]+)\\]$"; /* range regex pattern to parse '[x-y]' */
		regex_t range_reg;										  /* range regex */
		regmatch_t range_matches[3];
		S32 opt;

		dstaddr_file = NULL;
		ip_arg = NULL;
		timeout_flt = 0.1f;
		ports_min = 1;
		ports_max = 1024;
		thread_count = 0;
		g_scans = S_ALL;
		g_use_custom_interface = FALSE;

		if (UNLIKELY(regcomp(&range_reg, range_reg_src, REG_EXTENDED) != 0))
		{
			ft_fprintf(ft_fstderr, "%s: regex compilation error\n", ft_argv[0]);
			return 1;
		}

		while ((opt = ft_getopt_long(ft_argc, ft_argv, "f:hi:I:p:s:S:t:", long_opts, NULL)) != -1)
		{
			switch (opt)
			{
			case 'f':
				dstaddr_file = ft_optarg;
				break;

			case 'i':
				ip_arg = ft_optarg;
				break;

			case 'I':
			{
				struct ifaddrs *ifaddr, *ifa;
				struct sockaddr_in *sa;

				if (getifaddrs(&ifaddr) == -1)
				{
					ft_fprintf(ft_fstderr, "%s: getifaddrs: %s\n", ft_argv[0], strerror(errno));
					goto optarg_err;
				}

				g_srcaddr = 0;
				/* search for specified interface */
				for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next)
				{
					if (ifa->ifa_addr == NULL || ifa->ifa_addr->sa_family != AF_INET)
						continue;

					if (!ft_strcmp(ifa->ifa_name, ft_optarg))
					{ /* found match */
						sa = (struct sockaddr_in *)ifa->ifa_addr;
						g_srcaddr = sa->sin_addr.s_addr;
						break;
					}
				}
				if (g_srcaddr == 0)
				{
					ft_fprintf(ft_fstderr, "%s: couldn't find interface: %s\n", ft_argv[0], ft_optarg);
					freeifaddrs(ifaddr);
					goto optarg_err;
				}
				freeifaddrs(ifaddr);
			}
				g_use_custom_interface = TRUE;
				break;

			case 'p':
				if (regexec(&range_reg, ft_optarg, array_len(range_matches), range_matches, 0) == REG_NOMATCH)
				{
					ft_fprintf(ft_fstderr, "%s: invalid port range: '%s'\n", ft_argv[0], ft_optarg);
					goto optarg_err;
				}

				string str = ft_strdup(ft_optarg);
				if (UNLIKELY(str == NULL))
				{
					ft_fprintf(ft_fstderr, "%s: out of memory\n", ft_argv[0]);
					goto optarg_err;
				}
				str[range_matches[1].rm_eo] = '\0';
				str[range_matches[2].rm_eo] = '\0';
				if (!ft_str_isdigit(str + range_matches[1].rm_so) || !ft_str_isdigit(str + range_matches[2].rm_so))
				{
					ft_fprintf(ft_fstderr, "%s: invalid port range: '%s'\n", ft_argv[0], ft_optarg);
					free(str);
					goto optarg_err;
				}
				i = ft_atoi(str + range_matches[1].rm_so);
				j = ft_atoi(str + range_matches[2].rm_so);
				free(str);
				if ((i < 1 || i > U16_MAX || j < 1 || j > U16_MAX) || (j < i))
				{
					ft_fprintf(ft_fstderr, "%s: invalid port range: '%s'\n", ft_argv[0], ft_optarg);
					goto optarg_err;
				}
				ports_min = i;
				ports_max = j;
				break;

			case 's':
				if (!ft_str_isnbr((string)ft_optarg))
				{
					ft_dprintf(ft_errno, "%s: invalid argument: '%s'\n", ft_argv[0], ft_optarg);
					goto optarg_err;
				}
				i = ft_atoi(ft_optarg);
				if (i < 1 || i > U16_MAX)
				{
					ft_dprintf(ft_errno, "%s: invalid argument: '%s': out of range: 1 <= value <= 250\n", ft_argv[0], ft_optarg);
					goto optarg_err;
				}
				thread_count = i;
				break;

			case 'S':
				g_scans = str_to_scan(ft_optarg);
				if (g_scans == 0)
				{
					ft_dprintf(ft_errno, "%s: invalid argument: '%s'\n", ft_argv[0], ft_optarg);
					goto optarg_err;
				}
				break;

			case 't':
				if (!ft_str_isflt(ft_optarg))
				{
					ft_dprintf(ft_errno, "%s: invalid argument: '%s'\n", ft_argv[0], ft_optarg);
					goto optarg_err;
				}
				timeout_flt = ft_atof(ft_optarg);
				if (timeout_flt <= 0)
				{
					ft_dprintf(ft_errno, "%s: invalid argument: '%s'\n", ft_argv[0], ft_optarg);
					goto optarg_err;
				}
				break;

			case '?':
			case 'h':
				print_help();
				regfree(&range_reg);
				return 0;
			}

			continue;
		optarg_err:
			regfree(&range_reg);
			return 1;
		}
		regfree(&range_reg);

		it = address_iterator_init(ports_min, ports_max);
		{ /* fill destination addresses */
			if (ip_arg)
			{
				if (!address_iterator_ingest(it, ip_arg))
					goto exit_err;
			}

			for (i = ft_optind; i < ft_argc; i++)
			{ /* ingest arguments */
				if (!address_iterator_ingest(it, ft_argv[i]))
					goto exit_err;
			}

			if (dstaddr_file != NULL)
			{ /* ingest address file */
				filedesc fd = ft_open(dstaddr_file, "r");
				if (fd == (filedesc)-1)
				{
					ft_fprintf(ft_fstderr, "%s: couldn't open file '%s': %s\n", ft_argv[0], dstaddr_file, ft_strerror2(ft_errno));
					goto exit_err;
				}

				string file = (string)ft_readfile(fd, NULL);
				if (file == NULL)
				{
					ft_fprintf(ft_fstderr, "%s: out of memory\n", ft_argv[0]);
					ft_close(fd);
					goto exit_err;
				}

				string st = file;
				string ptr = file;
				while (*ptr)
				{
					if (*ptr == '\n')
					{
						if (st == ptr)
						{
							ptr++;
							st++;
							continue;
						}
						*ptr = '\0';
						if (!address_iterator_ingest(it, st))
						{
							if (ft_errno != 0)
								ft_fprintf(ft_fstderr, "%s: %s\n", ft_argv[0], ft_strerror2(ft_errno));
							else
								ft_fprintf(ft_fstderr, "%s: malformed address: %s\n", ft_argv[0], st);
							free(file);
							ft_close(fd);
							goto exit_err;
						}
						st = ptr + 1;
					}
					ptr++;
				}
				free(file);
				ft_close(fd);
			}
		}
	}

	if (address_iterator_total(it) == 0)
	{
		ft_fprintf(ft_fstderr, "%s: no valid address specified\n", ft_argv[0]);
		goto exit_err;
	}

	scan_to_str(g_scans, buf, sizeof(buf));
	printf("Ports: %u-%u\n", ports_min, ports_max);
	printf("Thread count: %u\n", thread_count);
	printf("Scan method: %s\n", buf);

	if (timeout_flt < 0.1f)
		printf("Warning: timeout of %f is probably not enough\n", timeout_flt);
	g_timeout.seconds = timeout_flt;
	g_timeout.nanoseconds = (timeout_flt - g_timeout.seconds) * 1e6; // microseconds, pas nano

	if (!address_iterator_prepare(it))
	{
		// TODO:
		return 1;
	}

	if (thread_count == 0)
	{
		if (g_scans & S_UDP)
			run_test_udp(it);
		else
			run_test(it);
	}
	else
	{
		if (UNLIKELY((threads = malloc(sizeof(pthread_t) * thread_count)) == NULL))
		{
			ft_fprintf(ft_fstderr, "%s: out of memory\n", ft_argv[0]);
			goto exit_err;
		}

		/* launch threads */
		for (i = 0; i < thread_count; i++)
		{
			if (pthread_create(&threads[i], NULL, (void *(*)(void *))run_test, it) != 0)
			{
				for (j = 0; j < i; j++)
				{
					pthread_kill(threads[j], SIGINT);
					pthread_join(threads[i], NULL);
				}
				free(threads);
				ft_fprintf(ft_fstderr, "%s: pthread_create: %s\n", ft_argv[0], ft_strerror2(ft_errno));
				goto exit_err;
			}
		}

		for (i = 0; i < thread_count; i++)
			pthread_join(threads[i], NULL);
		free(threads);
	}
	address_iterator_results(it);
	address_iterator_destroy(it);
	return 0;
exit_err:
	address_iterator_destroy(it);
	return 1;
}

static void print_help()
{
	ft_printf(
		"Usage\n\
  %s [options] <target>\n\
\n\
Options:\n\
  <target>                        dns name or ip address\n\
  -f (--file) <filename>          file name containing list of IPs to scan\n\
  -h (--help)                     print help and exit\n\
  -i (--ip) <IP address>          ip address to scan\n\
  -I (--interface) <Interface>    interface to use\n\
  -p (--ports) <ports>            port range to scan\n\
  -s (--speedup) <threads>        number of parallel threads to use [1;250]\n\
  -S (--scan)                     scan method to use. Can be any combination of SYN/NULL/FIN/XMAS/ACK/UDP\n\
  -t (--timeout) <timeout>        sockets timeout\n",
		ft_argv[0]);
}
