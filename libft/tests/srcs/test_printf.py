import random

fmt_set = "di"
flagset = "# -+0"
flags_n = 5
padding = True
precision = True
positional_args = True

tests_n = 100

tests = ""
for i in range(tests_n):
	args = ""

	tests += "TEST_PRINTF(\"%"
	tests += "".join(random.choices(flagset, k=flags_n))

	if (padding and random.randint(0, 1) == 1):
		tests += f"{random.randint(0, 99)}"
	if (precision and random.randint(0, 1) == 1):
		tests += f".{random.randint(0, 99)}"

	fmt = random.choice(fmt_set)
	tests += fmt
	tests += "\", "
	if (fmt == "d" or fmt == "i"):
		tests += f"{random.randint(-2147483648, 2147483647)}"
	tests += ");\n"

print(tests)
