#ifndef CRYPTOFS_CONFIGS_H
#define CRYPTOFS_CONFIGS_H

class Configs {
public:



private:
    const static int MaxFuseArgc = 32;
    char *mountPoint;
    char *fuseArgv[MaxFuseArgc];
    int fuseArgc;
};

#endif
