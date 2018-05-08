#include <fuse.h>
#include <sys/stat.h>
#include <iostream>

using namespace std;

static struct fuse_operations operations = {
};


int main (int argc, char **argv) {
    return fuse_main( argc, argv, &operations);
}
