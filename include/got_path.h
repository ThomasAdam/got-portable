/* Utilities for dealing with filesystem paths. */

/* Determine whether a path is an absolute path. */
int got_path_is_absolute(const char *);

/*
 * Return an absolute version of a relative path.
 * The result is allocated with malloc(3).
 */
char *got_path_get_absolute(const char *);

/* 
 * Normalize a path for internal processing.
 * The result is allocated with malloc(3).
 */
char *got_path_normalize(const char *);
