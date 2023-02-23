/*
 * Copyright (c) 2022 Josh Rickmar <jrick@zettaport.com>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/queue.h>
#include <sys/wait.h>

#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <err.h>
#include <assert.h>
#include <sha2.h>

#include "got_error.h"
#include "got_date.h"
#include "got_object.h"
#include "got_opentemp.h"

#include "got_sigs.h"
#include "got_compat.h"
#include "buf.h"

#ifndef MIN
#define	MIN(_a,_b) ((_a) < (_b) ? (_a) : (_b))
#endif

#ifndef nitems
#define nitems(_a)	(sizeof((_a)) / sizeof((_a)[0]))
#endif

#ifndef GOT_TAG_PATH_SSH_KEYGEN
#define GOT_TAG_PATH_SSH_KEYGEN	"/usr/bin/ssh-keygen"
#endif

#ifndef GOT_TAG_PATH_SIGNIFY
#define GOT_TAG_PATH_SIGNIFY "/usr/bin/signify"
#endif

const struct got_error *
got_sigs_apply_unveil(void)
{
	if (unveil(GOT_TAG_PATH_SSH_KEYGEN, "x") != 0) {
		return got_error_from_errno2("unveil",
		    GOT_TAG_PATH_SSH_KEYGEN);
	}
	if (unveil(GOT_TAG_PATH_SIGNIFY, "x") != 0) {
		return got_error_from_errno2("unveil",
		    GOT_TAG_PATH_SIGNIFY);
	}

	return NULL;
}

const struct got_error *
got_sigs_sign_tag_ssh(pid_t *newpid, int *in_fd, int *out_fd,
    const char* key_file, int verbosity)
{
	const struct got_error *error = NULL;
	int pid, in_pfd[2], out_pfd[2];
	const char* argv[11];
	int i = 0, j;

	*newpid = -1;
	*in_fd = -1;
	*out_fd = -1;

	argv[i++] = GOT_TAG_PATH_SSH_KEYGEN;
	argv[i++] = "-Y";
	argv[i++] = "sign";
	argv[i++] = "-f";
	argv[i++] = key_file;
	argv[i++] = "-n";
	argv[i++] = "git";
	if (verbosity <= 0) {
		argv[i++] = "-q";
	} else {
		/* ssh(1) allows up to 3 "-v" options. */
		for (j = 0; j < MIN(3, verbosity); j++)
			argv[i++] = "-v";
	}
	argv[i++] = NULL;
	assert(i <= nitems(argv));

	if (pipe(in_pfd) == -1)
		return got_error_from_errno("pipe");
	if (pipe(out_pfd) == -1)
		return got_error_from_errno("pipe");

	pid = fork();
	if (pid == -1) {
		error = got_error_from_errno("fork");
		close(in_pfd[0]);
		close(in_pfd[1]);
		close(out_pfd[0]);
		close(out_pfd[1]);
		return error;
	} else if (pid == 0) {
		if (close(in_pfd[1]) == -1)
			err(1, "close");
		if (close(out_pfd[0]) == -1)
			err(1, "close");
		if (dup2(in_pfd[0], 0) == -1)
			err(1, "dup2");
		if (dup2(out_pfd[1], 1) == -1)
			err(1, "dup2");
		if (execv(GOT_TAG_PATH_SSH_KEYGEN, (char **const)argv) == -1)
			err(1, "execv");
		abort(); /* not reached */
	}
	if (close(in_pfd[0]) == -1)
		return got_error_from_errno("close");
	if (close(out_pfd[1]) == -1)
		return got_error_from_errno("close");
	*newpid = pid;
	*in_fd = in_pfd[1];
	*out_fd = out_pfd[0];
	return NULL;
}

static char *
signer_identity(const char *tagger)
{
	char *lt, *gt;

	lt = strstr(tagger, " <");
	gt = strrchr(tagger, '>');
	if (lt && gt && lt+1 < gt)
		return strndup(lt+2, gt-lt-2);
	return NULL;
}

static const char* BEGIN_SSH_SIG = "-----BEGIN SSH SIGNATURE-----\n";
static const char* END_SSH_SIG = "-----END SSH SIGNATURE-----\n";

const char *
got_sigs_get_tagmsg_ssh_signature(const char *tagmsg)
{
	const char *s = tagmsg, *begin = NULL, *end = NULL;

	while ((s = strstr(s, BEGIN_SSH_SIG)) != NULL) {
		begin = s;
		s += strlen(BEGIN_SSH_SIG);
	}
	if (begin)
		end = strstr(begin+strlen(BEGIN_SSH_SIG), END_SSH_SIG);
	if (end == NULL)
		return NULL;
	return (end[strlen(END_SSH_SIG)] == '\0') ? begin : NULL;
}

static const struct got_error *
got_tag_write_signed_data(BUF *buf, struct got_tag_object *tag,
    const char *start_sig)
{
	const struct got_error *err = NULL;
	struct got_object_id *id;
	char *id_str = NULL;
	char *tagger = NULL;
	const char *tagmsg;
	char gmtoff[6];
	size_t len;

	id = got_object_tag_get_object_id(tag);
	err = got_object_id_str(&id_str, id);
	if (err)
		goto done;

	const char *type_label = NULL;
	switch (got_object_tag_get_object_type(tag)) {
	case GOT_OBJ_TYPE_BLOB:
		type_label = GOT_OBJ_LABEL_BLOB;
		break;
	case GOT_OBJ_TYPE_TREE:
		type_label = GOT_OBJ_LABEL_TREE;
		break;
	case GOT_OBJ_TYPE_COMMIT:
		type_label = GOT_OBJ_LABEL_COMMIT;
		break;
	case GOT_OBJ_TYPE_TAG:
		type_label = GOT_OBJ_LABEL_TAG;
		break;
	default:
		break;
	}
	got_date_format_gmtoff(gmtoff, sizeof(gmtoff),
	    got_object_tag_get_tagger_gmtoff(tag));
	if (asprintf(&tagger, "%s %lld %s", got_object_tag_get_tagger(tag),
	    (long long)got_object_tag_get_tagger_time(tag), gmtoff) == -1) {
		err = got_error_from_errno("asprintf");
		goto done;
	}

	err = buf_puts(&len, buf, GOT_TAG_LABEL_OBJECT);
	if (err)
		goto done;
	err = buf_puts(&len, buf, id_str);
	if (err)
		goto done;
	err = buf_putc(buf, '\n');
	if (err)
		goto done;
	err = buf_puts(&len, buf, GOT_TAG_LABEL_TYPE);
	if (err)
		goto done;
	err = buf_puts(&len, buf, type_label);
	if (err)
		goto done;
	err = buf_putc(buf, '\n');
	if (err)
		goto done;
	err = buf_puts(&len, buf, GOT_TAG_LABEL_TAG);
	if (err)
		goto done;
	err = buf_puts(&len, buf, got_object_tag_get_name(tag));
	if (err)
		goto done;
	err = buf_putc(buf, '\n');
	if (err)
		goto done;
	err = buf_puts(&len, buf, GOT_TAG_LABEL_TAGGER);
	if (err)
		goto done;
	err = buf_puts(&len, buf, tagger);
	if (err)
		goto done;
	err = buf_puts(&len, buf, "\n");
	if (err)
		goto done;
	tagmsg = got_object_tag_get_message(tag);
	err = buf_append(&len, buf, tagmsg, start_sig-tagmsg);
	if (err)
		goto done;

done:
	free(id_str);
	free(tagger);
	return err;
}

const struct got_error *
got_sigs_verify_tag_ssh(char **msg, struct got_tag_object *tag,
    const char *start_sig, const char* allowed_signers, const char* revoked,
    int verbosity)
{
	const struct got_error *error = NULL;
	const char* argv[17];
	int pid, status, in_pfd[2], out_pfd[2];
	char* parsed_identity = NULL;
	const char *identity;
	char *tmppath = NULL;
	FILE *tmpsig = NULL;
	BUF *buf;
	int i = 0, j;

	*msg = NULL;

	error = got_opentemp_named(&tmppath, &tmpsig,
	    GOT_TMPDIR_STR "/got-tagsig", "");
	if (error)
		goto done;

	identity = got_object_tag_get_tagger(tag);
	parsed_identity = signer_identity(identity);
	if (parsed_identity != NULL)
		identity = parsed_identity;

	if (fputs(start_sig, tmpsig) == EOF) {
		error = got_error_from_errno("fputs");
		goto done;
	}
	if (fflush(tmpsig) == EOF) {
		error = got_error_from_errno("fflush");
		goto done;
	}

	error = buf_alloc(&buf, 0);
	if (error)
		goto done;
	error = got_tag_write_signed_data(buf, tag, start_sig);
	if (error)
		goto done;

	argv[i++] = GOT_TAG_PATH_SSH_KEYGEN;
	argv[i++] = "-Y";
	argv[i++] = "verify";
	argv[i++] = "-f";
	argv[i++] = allowed_signers;
	argv[i++] = "-I";
	argv[i++] = identity;
	argv[i++] = "-n";
	argv[i++] = "git";
	argv[i++] = "-s";
	argv[i++] = tmppath;
	if (revoked) {
		argv[i++] = "-r";
		argv[i++] = revoked;
	}
	if (verbosity > 0) {
		/* ssh(1) allows up to 3 "-v" options. */
		for (j = 0; j < MIN(3, verbosity); j++)
			argv[i++] = "-v";
	}
	argv[i++] = NULL;
	assert(i <= nitems(argv));

	if (pipe(in_pfd) == -1) {
		error = got_error_from_errno("pipe");
		goto done;
	}
	if (pipe(out_pfd) == -1) {
		error = got_error_from_errno("pipe");
		goto done;
	}

	pid = fork();
	if (pid == -1) {
		error = got_error_from_errno("fork");
		close(in_pfd[0]);
		close(in_pfd[1]);
		close(out_pfd[0]);
		close(out_pfd[1]);
		return error;
	} else if (pid == 0) {
		if (close(in_pfd[1]) == -1)
			err(1, "close");
		if (close(out_pfd[0]) == -1)
			err(1, "close");
		if (dup2(in_pfd[0], 0) == -1)
			err(1, "dup2");
		if (dup2(out_pfd[1], 1) == -1)
			err(1, "dup2");
		if (execv(GOT_TAG_PATH_SSH_KEYGEN, (char **const)argv) == -1)
			err(1, "execv");
		abort(); /* not reached */
	}
	if (close(in_pfd[0]) == -1) {
		error = got_error_from_errno("close");
		goto done;
	}
	if (close(out_pfd[1]) == -1) {
		error = got_error_from_errno("close");
		goto done;
	}
	if (buf_write_fd(buf, in_pfd[1]) == -1) {
		error = got_error_from_errno("write");
		goto done;
	}
	if (close(in_pfd[1]) == -1) {
		error = got_error_from_errno("close");
		goto done;
	}
	if (waitpid(pid, &status, 0) == -1) {
		error = got_error_from_errno("waitpid");
		goto done;
	}
	if (!WIFEXITED(status)) {
		error = got_error(GOT_ERR_BAD_TAG_SIGNATURE);
		goto done;
	}

	error = buf_load_fd(&buf, out_pfd[0]);
	if (error)
		goto done;
	error = buf_putc(buf, '\0');
	if (error)
		goto done;
	if (close(out_pfd[0]) == -1) {
		error = got_error_from_errno("close");
		goto done;
	}
	*msg = buf_get(buf);
	if (WEXITSTATUS(status) != 0)
		error = got_error(GOT_ERR_BAD_TAG_SIGNATURE);

done:
	free(parsed_identity);
	if (tmppath && unlink(tmppath) == -1 && error == NULL)
		error = got_error_from_errno("unlink");
	free(tmppath);
	close(out_pfd[0]);
	if (tmpsig && fclose(tmpsig) == EOF && error == NULL)
		error = got_error_from_errno("fclose");
	return error;
}
