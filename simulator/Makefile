SOURCE_FILES= main.c \
              lib/everflow.c \
              lib/hash.c \
              lib/keytracker.c \
              lib/motivation.c \
              lib/netsight.c \
              lib/packet.c \
              lib/sample.c

CFLAGS += -I./include -O2 -mcmodel=medium

LIBS= -lpcap

compile:
	@mkdir -p build
	@gcc -o build/keytracker $(SOURCE_FILES) $(LIBS) $(CFLAGS)

clean:
	@rm -f *.o
	@rm build/keytracker

