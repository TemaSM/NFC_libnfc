SRCS = uid-reader.c
OBJS = $(SRCS:.c=.o)
LIBS = nfc

CC = gcc
DEBUG = -g
CFLAGS = -Wall $(DEBUG) -std=c99 -c 
LFLAGS = -Wall $(DEBUG) -l $(LIBS)
EXE = uid-reader

all: $(EXE)

$(EXE): $(OBJS)
	$(CC) $(LFLAGS) $(OBJS) -o $@

.c.o:
	$(CC) $(CFLAGS) $< -o $@

clean:
	rm -rf *.o $(EXE)

