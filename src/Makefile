build : cryptofs.out
	sudo cp cryptofs.out /usr/bin
	sudo cp cryptofs /usr/bin

cryptofs.out : Configs.h Crypto.h Util.o cryptofs.o Structure.o
	g++ -std=c++11 -Wall cryptofs.o Structure.o Util.o `pkg-config fuse --cflags --libs` -o cryptofs.out -lcryptopp

cryptofs.o : Configs.h cryptofs.cpp
	g++ -c -std=c++11 -Wall cryptofs.cpp `pkg-config fuse --cflags --libs` -o cryptofs.o -lcryptopp

Structure.o : Configs.h Structure.h Structure.cpp
	g++ -c -std=c++11 -Wall Structure.cpp `pkg-config fuse --cflags --libs` -o Structure.o -lcryptopp

Util.o : Util.h Util.cpp Configs.h
	g++ -c -std=c++11 -Wall Util.cpp `pkg-config fuse --cflags --libs` -o Util.o -lcryptopp

mount : cryptofs 
	rm ./log.txt
	./cryptofs ./dir -o nonempty

umount : 
	sudo umount ./dir

