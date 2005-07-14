#include "stringlist.h"

#define NUM_ROWS_PER_MALLOC 100

static int sl_strcmp(const void *p1, const void *p2)
{
    return strcmp(*(char * const *)p1, *(char * const *)p2);
}

static int sl_strcasecmp(const void *p1, const void *p2)
{
    return strcasecmp(*(char * const *)p1, *(char * const *)p2);
}

/*
 * initialize the stringlist
 */
stringlist_t *sl_init(void)
{
    stringlist_t *sl;
    sl = (stringlist_t *)malloc(sizeof(stringlist_t));
    if (sl == NULL)
        return NULL;

    sl->lines = (char **)malloc(NUM_ROWS_PER_MALLOC * sizeof(char *));
    if (sl->lines == NULL)
        return NULL;
    sl->maxlines = NUM_ROWS_PER_MALLOC;
    sl->numlines = 0;
    sl->sorted = 0;
    return sl;
}
/*
 * free the stringlist
 */
void sl_free(stringlist_t *sl)
{
    size_t i;
    if (sl == NULL)
        return;
    if (sl->lines)
    {
        for (i=0; i < sl_count(sl); i++)
        {
            free(sl->lines[i]);
        }
        free(sl->lines);
    }
    free(sl);
}
/*
 * add string to stringlist
 * do_malloc: allocate memory for the string
 */
int sl_add(stringlist_t *sl, char *str, int do_malloc)
{
    /* resize the array if needed */
    if (sl->numlines == sl->maxlines -1)
    {
        char **new;
        new = (char **)realloc(sl->lines, (sl->maxlines + NUM_ROWS_PER_MALLOC)*sizeof(char *));
        if (new == NULL)
            return -1;
        sl->maxlines += NUM_ROWS_PER_MALLOC;
        sl->lines = new;
    }
    if (do_malloc)
    {
        sl->lines[sl->numlines] = (char *)malloc( (strlen(str)+1) * sizeof(char));
        if (sl->lines[sl->numlines] == NULL)
            return -1;
        strcpy(sl->lines[sl->numlines], str);
        sl->numlines++;
        sl->sorted = 0;
        return 0;
   }
   sl->lines[sl->numlines] = str;
   sl->numlines++;
   sl->sorted = 0;
   return 0;
}

/*
 * return the number of items in the stringlist
 */
size_t sl_count(stringlist_t *sl)
{
    return sl->numlines;
}

/*
 * return the item at the index: index
 */
char *sl_item(stringlist_t *sl, size_t index)
{
    if (sl_count(sl) == 0)
        return NULL;
    if (index > sl_count(sl))
    {
        return NULL;
    }
    return sl->lines[index];
}
/*
 * search for a item in the stringlist
 */
char *sl_find(stringlist_t *sl, const char *str)
{
    /* use binary search if stringlist is sorted */
    if (sl->sorted == 1)
        return bsearch (str, sl->lines, sl_count(sl), sizeof(char *), sl_strcasecmp);

    size_t i;
    for (i=0; i < sl_count(sl); i++)
    {
        if (strcmp(sl_item(sl, i), str) == 0)
            return sl_item(sl, i);
    }
    return NULL;
}

/*
 * case insensitive search
 */
char *sl_casefind(stringlist_t *sl, const char *str)
{
    /* use binary search if stringlist is case insensitively sorted */
    if (sl->sorted == 2)
        return bsearch (str, sl->lines, sl_count(sl), sizeof(char *), sl_strcasecmp);

    size_t i;
    for (i=0; i < sl_count(sl); i++)
    {
        if (strcasecmp(sl_item(sl, i), str) == 0)
            return sl_item(sl, i);
    }
    return NULL;
}

/*
 * case sensitive sort of the stringlist
 */
void sl_sort(stringlist_t *sl)
{
    qsort(sl->lines, sl_count(sl), sizeof(char *), sl_strcmp);
    sl->sorted = 1;
}

/*
 * case insensitive sort of the stringlist
 */
void sl_casesort(stringlist_t *sl)
{
    qsort(sl->lines, sl_count(sl), sizeof(char *), sl_strcasecmp);
    sl->sorted = 2;
}
