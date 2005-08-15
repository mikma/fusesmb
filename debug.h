#ifndef DEBUG_H
#define DEBUG_H

#if defined(__GNUC__) && !defined(__OPTIMIZE__)
#define debug(format, ...) fprintf(stderr, "%s: %s: %d " format "\n", __FILE__, __FUNCTION__, __LINE__, ##__VA_ARGS__)
#else
#define debug(format, ...)
#endif

#endif
