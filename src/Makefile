
cryptofs : Configs.h Crypto.h Util.h cryptofs.cpp
	g++ -std=c++11 -Wall cryptofs.cpp `pkg-config fuse --cflags --libs` -o cryptofs -lcryptopp

mount : cryptofs
	./cryptofs ~/Github/CryptoFS/src/cryptofs_test
umount : 
	sudo umount ~/Github/CryptoFS/src/cryptofs_test

