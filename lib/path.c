/* #include <sys/syslimits.h> */

#include <limits.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

int
got_path_is_absolute(const char *path)
{
	return path[0] == '/';
}

char *
got_path_get_absolute(const char *relpath) 
{
	char cwd[PATH_MAX];
	char *abspath;

	if (getcwd(cwd, sizeof(cwd)) == NULL)
		return NULL;

	if (asprintf(&abspath, "%s/%s/", cwd, relpath) == -1)
		return NULL;

	return abspath;
}

char *
got_path_normalize(const char *path)
{
	char *resolved;

	resolved = realpath(path, NULL);
	if (resolved == NULL)
		return NULL;
	
	if (!got_path_is_absolute(resolved)) {
		char *abspath = got_path_get_absolute(resolved);
		free(resolved);
		resolved = abspath;
	}

	return resolved;
}

int
got_path_is_normalized(const char *path)
{
	char *normpath;
	int ret;

	normpath = got_path_normalize(path);
	ret = (strcmp(normpath, path) == 0);
	free(normpath);

	return ret;
}
