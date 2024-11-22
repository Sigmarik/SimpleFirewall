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
	cp -r assets build

run_socks: socks
	cd build; ./cpp_socks $(ARGS)

nfqueue:
	python3 firewall.py $(ARGS)

setup_tables:
	iptables -t nat -F
	iptables -t mangle -F
	iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
	iptables -t mangle -A FORWARD -j NFQUEUE --queue-num 5
	iptables -t nat -L -v -n
	iptables -t mangle -L -v -n

rm:
	find . -name "*.o" -type f -not -path "./include/*" -delete
	find build ! -name '.gitkeep' -type f -delete

update:
	wget https://github.com/Sigmarik/SimpleFirewall/archive/refs/heads/master.zip -O ../SimpleFirewall.zip; unzip -o ../SimpleFirewall.zip -d ..

%.o: %.cpp
	@echo $(YELLOW)Building file $^$(STYLE_RESET)
	@$(CC) $(CPPFLAGS) -c $^ -o $@

install_everything:
	apk add python3-dev
	apk add iptables
	apk add linux-headers
	apk add vim
	apk add libnetfilter_queue-dev
	python3 -m ensurepip
	python3 -m pip install NetfilterQueue
