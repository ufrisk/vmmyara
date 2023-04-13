#
# NOTE! PACKAGE DEPENDENCY ON YARA:
#
CC=gcc
CFLAGS  += -I. -I../yara/libyara/include -D LINUX -D _GNU_SOURCE -shared -fPIC -fvisibility=hidden -L. -lm -pthread -lcrypto
# DEBUG FLAGS BELOW
#export ASAN_OPTIONS=strict_string_checks=1:detect_stack_use_after_return=1:check_initialization_order=1:strict_init_order=1:detect_invalid_pointer_pairs=2
#CFLAGS  += -g -O0 -Wextra -Wno-unused-parameter -Wno-cast-function-type
#CFLAGS  += -fsanitize=address -fsanitize=leak -fno-omit-frame-pointer -fsanitize=undefined -fsanitize=bounds-strict -fsanitize=float-divide-by-zero -fsanitize=float-cast-overflow
#CFLAGS  += -fsanitize=pointer-compare -fsanitize=pointer-subtract -fanalyzer
# DEBUG FLAGS ABOVE
CFLAGS  += -fPIE -fPIC -pie -fstack-protector -D_FORTIFY_SOURCE=2 -O1 -Wl,-z,noexecstack
CFLAGS  += -Wall -Wno-unused-result -Wno-unused-variable -Wno-unused-value -Wno-pointer-to-int-cast -Wno-int-to-pointer-cast
LDFLAGS += -shared -g -ldl -Wl,-Bstatic -L../yara/.libs -lyara -Wl,-Bdynamic -lcrypto
DEPS = vmmyara.h
OBJ = vmmyara.o

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

vmmyara: $(OBJ)
	$(CC) -o $@ $^ $(CFLAGS) -o vmmyara.so $(LDFLAGS)
	mkdir -p ../bin
	mv vmmyara.so ../bin/
	rm -f *.o || true
	rm -f */*.o || true
	rm -f *.so || true
	true

clean:
	rm -f *.o || true
	rm -f */*.o || true
	rm -f *.so || true
