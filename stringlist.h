#include <string.h>
#include <stdlib.h>

typedef struct stringlist {
    char **lines;
    size_t numlines;
    size_t maxlines;
    char sorted;
} stringlist_t;

stringlist_t *sl_init(void);
void sl_free(stringlist_t *sl);

inline int sl_add(stringlist_t *sl, char *str, int do_malloc);
inline size_t sl_count(stringlist_t *sl);
char *sl_find(stringlist_t *sl, const char *str);
char *sl_casefind(stringlist_t *sl, const char *str);
inline char *sl_item(stringlist_t *sl, size_t index);

void sl_sort(stringlist_t *sl);
void sl_casesort(stringlist_t *sl);
