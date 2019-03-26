#include "global.h"

#ifdef __cplusplus
extern "C"
{

void Sleep(int milliseconds) {
    usleep(milliseconds * 1000);
}

}
#endif