.DEFAULT_TARGET=libfttest.a


objs:
	mkdir objs

objs/create_tests.o: create_tests.c
	gcc -c create_tests.c -o objs/create_tests.o

objs/fuzzler.o: fuzzler.c
	gcc -c fuzzler.c -o objs/fuzzler.o

objs/main_perf.o: main_perf.c
	gcc -c main_perf.c -o objs/main_perf.o

objs/main_behaviour.o: main_behaviour.c
	gcc -c main_behaviour.c -o objs/main_behaviour.o


libfttest.a:
	