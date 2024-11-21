all: socks

CC = g++

SOCK_OBJECTS = $(shell cat socks.flist)

CPP_INCLUDE_FLAGS = -I./ -isystem ./include

CPPFLAGS = $(CPP_INCLUDE_FLAGS)

BOLD = \\033[1m
STYLE_RESET = \\033[0m

RED 	= \\033[31m
GREEN 	= \\033[32m
YELLOW 	= \\033[33m
BLUE 	= \\033[34m
PINK 	= \\033[35m
CYAN 	= \\033[36m
GREY 	= \\033[37m

socks: $(SOCK_OBJECTS)
	g++ $^ -o build/cpp_socks

run_socks: socks
	cd build; ./cpp_socks $(ARGS)

rm:
	find . -name "*.o" -type f -delete
	find build ! -name '.gitkeep' -type f -delete

%.o: %.cpp
	@echo $(YELLOW)Building file $^$(STYLE_RESET)
	@$(CC) $(CPPFLAGS) -c $^ -o $@
