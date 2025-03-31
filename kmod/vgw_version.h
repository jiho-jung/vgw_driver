#ifndef _VGW_VERION_H
#define _VGW_VERION_H

#include "define.h"

#ifndef MAJ_VER
#define MAJ_VER 1
#endif

#ifndef MIN_VER
#define MIN_VER 0
#endif

#ifndef REV_VER
#define REV_VER 0
#endif

#define VERSION_STRING "v" STR(MAJ_VER) "." STR(MIN_VER) "." STR(REV_VER)

#endif
