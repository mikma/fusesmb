#ifndef DEBUG_H
#define DEBUG_H

#ifndef __OPTIMIZE__
#define debug(format, ...) fprintf(stderr, "%s: %s: %d " format "\n", __FILE__, __FUNCTION__, __LINE__, ##__VA_ARGS__)
#else
#define debug(format, ...)
#endif

#endif
