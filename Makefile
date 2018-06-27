build : 
	cd src; make

# CC=g++
# CXXFLAGS=-Wall -std=c++11 -lcryptopp
# srcdir=src
# testdir=$(srcdir)/test
# builddir=build
# docdir=doc
# pdfdir=pdf
# 
# srcfile=
# 
# $(builddir):
# 	mkdir $(builddir)
# 
# crypto_test: $(builddir) $(testdir)/CryptoTest.cpp
# 	$(CC) $(testdir)/CryptoTest.cpp $(srcfile) -o $(builddir)/CryptoTest $(CXXFLAGS)
# 
# 
# doc: security_note
# 
# $(pdfdir):
# 	mkdir $(pdfdir)
# 
# security_note: $(pdfdir) $(docdir)/security_note.tex
# 	pdflatex -output-directory=$(pdfdir) $(docdir)/security_note.tex
# 
# 
