
cryptofs : Configs.h Crypto.h Util.o cryptofs.o Structure.o
	g++ -std=c++11 -Wall cryptofs.o Structure.o Util.o `pkg-config fuse --cflags --libs` -o cryptofs -lcryptopp

cryptofs.o : Configs.h cryptofs.cpp
	g++ -c -std=c++11 -Wall cryptofs.cpp `pkg-config fuse --cflags --libs` -o cryptofs.o -lcryptopp

Structure.o : Configs.h Structure.h Structure.cpp
	g++ -c -std=c++11 -Wall Structure.cpp `pkg-config fuse --cflags --libs` -o Structure.o -lcryptopp

Util.o : Util.h Util.cpp Configs.h
	g++ -c -std=c++11 -Wall Util.cpp `pkg-config fuse --cflags --libs` -o Util.o -lcryptopp

mount : cryptofs
	./cryptofs ~/Github/CryptoFS/src/cryptofs_test
umount : 
	sudo umount ~/Github/CryptoFS/src/cryptofs_test

