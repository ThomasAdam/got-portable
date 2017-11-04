struct got_repository {
	char *path;
};

/* Open and close git repositories. */
const struct got_error *got_repo_open(struct got_repository**, const char *);
void got_repo_close(struct got_repository*);

/* Get the absolute path to the top-level directory of a repository. */
const char *got_repo_get_path(struct got_repository *);

/* Get a reference, by name, from a repository. */
const struct got_error *got_repo_get_reference(struct got_reference **,
    struct got_repository *, const char *);
