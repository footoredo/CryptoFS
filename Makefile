CC=g++
CXXFLAGS=-Wall -std=c++11 -lcryptopp
srcdir=src
testdir=$(srcdir)/test
builddir=build

srcfile=

$(builddir):
	mkdir $(builddir)

crypto_test: $(builddir) $(testdir)/CryptoTest.cpp
	$(CC) $(testdir)/CryptoTest.cpp $(srcfile) -o $(builddir)/CryptoTest $(CXXFLAGS)
