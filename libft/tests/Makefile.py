#!python3

import os
import sys
import subprocess
from glob import glob
import argparse
import datetime
import re

verbose = False
def log(*args, **kwargs):
	if (verbose):
		print(*args, **kwargs)

def _execute(*exe_args):
	log(' '.join(exe_args))
	try:
		process = subprocess.Popen(exe_args, shell=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
	except FileNotFoundError:
		print(f"Error: '{exe_args[0]}' doesn't exist. Double check args sent to subprocess.Popen.")
		exit(1)

	stdout, stderr = process.communicate()
	if (process.returncode != 0):
		print(f"Error: subprocess returned with error code: {process.returncode}")
		print(stderr.decode())
	return (stdout, stderr, process.returncode)

def _execute_nopipe(*exe_args):
	log(' '.join(exe_args))
	try:
		process = subprocess.Popen(exe_args, shell=False)
	except FileNotFoundError:
		print(f"Error: '{exe_args[0]}' doesn't exist. Double check args sent to subprocess.Popen.")
		exit(1)

def _get_platform():
	is_wsl = os.environ.get("WSLENV", default=None) != None

	is_win = sys.platform == "win32" or is_wsl
	is_linux = (sys.platform == "linux" or sys.platform == "linux2") and not is_wsl
	is_osx = sys.platform == "darwin" and not is_wsl
	return "win32" if (is_win) else "linux" if (is_linux) else "osx" if (is_osx) else None

parser = argparse.ArgumentParser(description='Custom makefile')


parser.add_argument('-s', '--single', metavar='SINGLE', type=str, help="The single test to run")

to_run = parser.add_mutually_exclusive_group()
to_run.add_argument('-p', '--performance', action='store_true', help="Run performance only")
to_run.add_argument('-b', '--behaviour', action='store_true', help="Run behaviour only")

parser.add_argument('-v', '--verbose', action='store_true', help="Verbose mode")
parser.add_argument('-t', '--target', metavar='TARGET', type=str, choices=['win32', 'linux', 'osx'], help='Specify the target platform. Build for current architecture if not specified.')
parser.add_argument('-D', metavar='DEFINE', type=str, nargs='+', help='Defines')

args = parser.parse_args()

run_behaviour = True
run_performance = True
if (args.performance):
	run_behaviour = False
if (args.behaviour):
	run_performance = False


RM=["rm", "-rf"]

INCLUDES=["-I../", "-I./"]
LIBRARIES_PATH=["-L../"]
LIBRARIES=["-lft"]
#CFLAGS=["-O3", "-g"]
CFLAGS=["-g"]

if (args.target):
	platform = args.target
else:
	platform = _get_platform()

if (platform == "win32"):
	CC="x86_64-w64-mingw32-gcc"
	CFLAGS += ["-D FT_OS_WIN"]
elif (platform == "linux"):
	CC="gcc"
	CFLAGS += ["-D FT_OS_LINUX"]
elif (platform == "osx"):
	CFLAGS += ["-D FT_OS_MAC"]
else:
	print("Platform not supported")
	exit(1)

if (args.D):
	CFLAGS += [f"-D {define}" for define in args.D]

NAME_BEHAVIOUR="run_tests_behaviour"
NAME_PERF="run_tests_perf"

SRCS_DIR="./srcs"
SRCS_EXT=".c"

SRCS=glob(f'{SRCS_DIR}/**/*{SRCS_EXT}', recursive=True)

def write_error_log(source_file:str, test_name:str, error_code:int, stdout:str, stderr:str):
	if (not os.path.isdir("./error_logs")):
		os.mkdir("./error_logs")
	date = datetime.datetime.now()

	source_file = os.path.split(os.path.abspath(source_file))[1]

	log_file = f"./error_logs/{source_file.removesuffix('.c')}_{date.strftime('%d-%m-%Y.%H-%M-%S')}_{test_name}.log"
	with open(log_file, 'w+') as f:
		f.write("====BEGIN LOG====\n")
		f.write(f"Code: {error_code}\n")
		f.write("=================\n")
		f.write(stdout)
		f.write("\n")
		f.write("=================\n")
		f.write(stderr)
		f.write("\n")

def run_init(source_file):
	with open(source_file, 'r') as f:
		line = f.readline()
		rmatch:re.Match[str]|None
		rmatch = None
		while line:
			if (line.startswith("//")):
				line = f.readline()
				continue
			rmatch = re.match(r"%%(\w+)%%=([^\n]*.*)", line)
			if (rmatch):
				key=rmatch.group(1)
				value=rmatch.group(2)
				print(key, value)
			line = f.readline()

def run_behaviour_test(source_file):
	run_init(source_file)
	stdout, stderr, return_code = _execute(CC, *CFLAGS, *INCLUDES, *LIBRARIES_PATH, source_file, 'run_behaviour.c', 'create_tests.c', '-o', NAME_BEHAVIOUR, *LIBRARIES)
	if (return_code != 0):
		print(f"{args.single}: compilation failed")
		write_error_log(source_file, "behaviour_compilation", return_code, stdout.decode(), stderr.decode())
		return
	
	exe = f"./{NAME_BEHAVIOUR}.exe" if platform == "win32" else f"./{NAME_BEHAVIOUR}"
	_execute_nopipe(exe)

def run_performance_test(source_file):
	stdout, stderr, return_code = _execute(CC, *CFLAGS, *INCLUDES, *LIBRARIES_PATH, source_file, 'run_performance.c', 'create_tests.c', '-o', NAME_PERF, *LIBRARIES)
	if (return_code != 0):
		print(f"{args.single}: compilation failed")
		write_error_log(source_file, "perf_compilation", return_code, stdout.decode(), stderr.decode())
		return

	exe = f"./{NAME_PERF}.exe" if platform == "win32" else f"./{NAME_PERF}"
	stdout, stderr, return_code = _execute(exe)
	stdout = stdout.decode()
	stderr = stderr.decode()
	if (return_code != 0):
		print(f"{args.single}: tests failed")
		write_error_log(source_file, "performance", return_code, stdout, stderr)
	
	if (not os.path.isdir("./perf_logs")):
		os.mkdir("./perf_logs")
	source_file = os.path.split(os.path.abspath(source_file))[1]
	log_file = f"./perf_logs/{source_file.removesuffix('.c')}.log"
	if (os.path.isfile(log_file)):
		with open(log_file, 'r') as f:
			matches = re.findall(r'\s+(\w+):\s+([\d.]+)', f.read())
			prev = {key: float(value) for key, value in matches}

		matches = re.findall(r'\s+(\w+):\s+([\d.]+)', stdout)
		curr = {key: float(value) for key, value in matches}

		for i, j in zip(prev.keys(), curr.keys()):
			print(f"{j}: {curr[j]} : {curr[j] - prev[i]}")

	else:
		matches = re.findall(r'\s+(\w+):\s+([\d.]+)', stdout)
		curr = {key: float(value) for key, value in matches}
		for k in curr.keys():
			print(f"{k}: {curr[k]}")
	with open(log_file, 'w+') as f:
		f.write(stdout)

def single():
	try:
		index = [os.path.split(os.path.abspath(s))[1] for s in SRCS].index(args.single)
	except ValueError:
		print(f"'{args.single}' not found in sources.")
		exit(1)
	if (run_behaviour):
		run_behaviour_test(SRCS[index])
	if (run_performance):
		run_performance_test(SRCS[index])


def all():
	for src in SRCS:
		if (run_behaviour):
			run_behaviour_test(src)
		if (run_performance):
			run_performance_test(src)

if (args.single):
	single()
else:
	all()