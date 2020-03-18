/*
 * Copyright (c) 2019 Ori Bernstein <ori@openbsd.org>
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

#include <sys/queue.h>
#include <sys/stat.h>
#include <sys/syslimits.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/uio.h>

#include <stdint.h>
#include <errno.h>
#include <imsg.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <sha1.h>
#include <fcntl.h>
#include <zlib.h>
#include <err.h>
#include <assert.h>
#include <dirent.h>

#include "got_error.h"
#include "got_object.h"

#include "got_lib_sha1.h"
#include "got_lib_delta.h"
#include "got_lib_inflate.h"
#include "got_lib_object.h"
#include "got_lib_object_parse.h"
#include "got_lib_object_idset.h"
#include "got_lib_privsep.h"

typedef struct Cinfo	Cinfo;
typedef struct Tinfo	Tinfo;
typedef struct Object	Object;
typedef struct Pack	Pack;
typedef struct Buf	Buf;
typedef struct Dirent	Dirent;
typedef struct Idxent	Idxent;
typedef struct Ols	Ols;

enum {
	/* 5k objects should be enough */
	Cachemax	= 5*1024,
	Pathmax		= 512,
	Hashsz		= 20,
	Pktmax		= 65536,

	Nproto	= 16,
	Nport	= 16,
	Nhost	= 256,
	Npath	= 128,
	Nrepo	= 64,
	Nbranch	= 32,
};

typedef enum Type {
	GNone	= 0,
	GCommit	= 1,
	GTree	= 2,
	GBlob	= 3,
	GTag	= 4,
	GOdelta	= 6,
	GRdelta	= 7,
} Type;

enum {
	Cloaded	= 1 << 0,
	Cidx	= 1 << 1,
	Ccache	= 1 << 2,
	Cexist	= 1 << 3,
	Cparsed	= 1 << 5,
};

struct Dirent {
	char *name;
	int modref;
	int mode;
	struct got_object_id h;
};

struct Object {
	/* Git data */
	struct got_object_id	hash;
	Type	type;

	/* Cache */
	int	id;
	int	flag;
	int	refs;
	Object	*next;
	Object	*prev;

	/* For indexing */
	off_t	off;
	off_t	len;
	uint32_t	crc;

	/* Everything below here gets cleared */
	char	*all;
	char	*data;
	/* size excludes header */
	off_t	size;

	union {
		Cinfo *commit;
		Tinfo *tree;
	};
};

struct Tinfo {
	/* Tree */
	Dirent	*ent;
	int	nent;
};

struct Cinfo {
	/* Commit */
	struct got_object_id	*parent;
	int	nparent;
	struct got_object_id	tree;
	char	*author;
	char	*committer;
	char	*msg;
	int	nmsg;
	off_t	ctime;
	off_t	mtime;
};

typedef struct Buf Buf;

struct Buf {
	int len;
	int sz;
	char *data;
};

static int	readpacked(FILE *, Object *, int);
static Object	*readidxobject(FILE *, struct got_object_id, int);

struct got_object_idset *objcache;
int	next_object_id;
Object *lruhead;
Object *lrutail;
int	ncache;

#define GETBE16(b)\
		((((b)[0] & 0xFFul) <<  8) | \
		 (((b)[1] & 0xFFul) <<  0))

#define GETBE32(b)\
		((((b)[0] & 0xFFul) << 24) | \
		 (((b)[1] & 0xFFul) << 16) | \
		 (((b)[2] & 0xFFul) <<  8) | \
		 (((b)[3] & 0xFFul) <<  0))
#define GETBE64(b)\
		((((b)[0] & 0xFFull) << 56) | \
		 (((b)[1] & 0xFFull) << 48) | \
		 (((b)[2] & 0xFFull) << 40) | \
		 (((b)[3] & 0xFFull) << 32) | \
		 (((b)[4] & 0xFFull) << 24) | \
		 (((b)[5] & 0xFFull) << 16) | \
		 (((b)[6] & 0xFFull) <<  8) | \
		 (((b)[7] & 0xFFull) <<  0))

#define PUTBE16(b, n)\
	do{ \
		(b)[0] = (n) >> 8; \
		(b)[1] = (n) >> 0; \
	} while(0)

#define PUTBE32(b, n)\
	do{ \
		(b)[0] = (n) >> 24; \
		(b)[1] = (n) >> 16; \
		(b)[2] = (n) >> 8; \
		(b)[3] = (n) >> 0; \
	} while(0)

#define PUTBE64(b, n)\
	do{ \
		(b)[0] = (n) >> 56; \
		(b)[1] = (n) >> 48; \
		(b)[2] = (n) >> 40; \
		(b)[3] = (n) >> 32; \
		(b)[4] = (n) >> 24; \
		(b)[5] = (n) >> 16; \
		(b)[6] = (n) >> 8; \
		(b)[7] = (n) >> 0; \
	} while(0)

static int
charval(int c, int *err)
{
	if(c >= '0' && c <= '9')
		return c - '0';
	if(c >= 'a' && c <= 'f')
		return c - 'a' + 10;
	if(c >= 'A' && c <= 'F')
		return c - 'A' + 10;
	*err = 1;
	return -1;
}

static int
hparse(struct got_object_id *h, char *b)
{
	int i, err;

	err = 0;
	for(i = 0; i < sizeof(h->sha1); i++){
		err = 0;
		h->sha1[i] = 0;
		h->sha1[i] |= ((charval(b[2*i], &err) & 0xf) << 4);
		h->sha1[i] |= ((charval(b[2*i+1], &err)& 0xf) << 0);
		if(err)
			return -1;
	}
	return 0;
}

static void *
emalloc(size_t n)
{
	void *v;

	v = calloc(n, 1);
	if(v == NULL)
		err(1, "malloc:");
	return v;
}

static void *
erealloc(void *p, ulong n)
{
	void *v;

	v = realloc(p, n);
	if(v == NULL)
		err(1, "realloc:");
	memset(v, 0, n);
	return v;
}

static int
hasheq(struct got_object_id *a, struct got_object_id *b)
{
	return memcmp(a->sha1, b->sha1, sizeof(a->sha1)) == 0;
}

static char *
typestr(int t)
{
	char *types[] = {
		"???",
		"commit",
		"tree",
		"blob",
		"tag",
		"odelta",
		"rdelta",
	};
	if (t < 0 || t >= sizeof(types)/sizeof(types[0]))
		abort();
	return types[t];
}

static char *
hashfmt(char *out, size_t nout, struct got_object_id *h)
{
	int i, n, c0, c1;
	char *p;

	if (nout < 2*sizeof(h->sha1) + 1)
		return NULL;
	p = out;
	for(i = 0; i < sizeof(h->sha1); i++){
		n = (h->sha1[i] >> 4) & 0xf;
		c0 = (n >= 10) ? n-10 + 'a' : n + '0';
		n = h->sha1[i] & 0xf;
		c1 = (n >= 10) ? n-10 + 'a' : n + '0';
		*p++ = c0;
		*p++ = c1;
	}
	*p++ = 0;
	return out;
}

static void
clear(Object *o)
{
	if(!o)
		return;

	assert(o->refs == 0);
	assert((o->flag & Ccache) == 0);
	assert(o->flag & Cloaded);
	switch(o->type){
	case GCommit:
		if(!o->commit)
			break;
		free(o->commit->parent);
		free(o->commit->author);
		free(o->commit->committer);
		free(o->commit);
		o->commit = NULL;
		break;
	case GTree:
		if(!o->tree)
			break;
		free(o->tree->ent);
		free(o->tree);
		o->tree = NULL;
		break;
	default:
		break;
	}

	free(o->all);
	o->all = NULL;
	o->data = NULL;
	o->flag &= ~Cloaded;
}

static void
unref(Object *o)
{
	if(!o)
		return;
	o->refs--;
	if(!o->refs)
		clear(o);
}

static Object*
ref(Object *o)
{
	o->refs++;
	return o;
}

static void
cache(Object *o)
{
	char buf[41];
	Object *p;

	hashfmt(buf, sizeof(buf), &o->hash);
	if(o == lruhead)
		return;
	if(o == lrutail)
		lrutail = lrutail->prev;
	if(!(o->flag & Cexist)){
		got_object_idset_add(objcache, &o->hash, o);
		o->id = next_object_id++;
		o->flag |= Cexist;
	}
	if(o->prev)
		o->prev->next = o->next;
	if(o->next)
		o->next->prev = o->prev;
	if(lrutail == o){
		lrutail = o->prev;
		lrutail->next = NULL;
	}else if(!lrutail)
		lrutail = o;
	if(lruhead)
		lruhead->prev = o;
	o->next = lruhead;
	o->prev = NULL;
	lruhead = o;

	if(!(o->flag & Ccache)){
		o->flag |= Ccache;
		ref(o);
		ncache++;
	}
	while(ncache > Cachemax){
		p = lrutail;
		lrutail = p->prev;
		lrutail->next = NULL;
		p->flag &= ~Ccache;
		p->prev = NULL;
		p->next = NULL;
		unref(p);
		ncache--;
	}
}

static int
preadbe32(FILE *b, int *v, off_t off)
{
	char buf[4];

	if(fseek(b, off, SEEK_SET) == -1)
		return -1;
	if(fread(buf, 1, sizeof(buf), b) == -1)
		return -1;
	*v = GETBE32(buf);

	return 0;
}
static int
preadbe64(FILE *b, off_t *v, off_t off)
{
	char buf[8];

	if(fseek(b, off, SEEK_SET) == -1)
		return -1;
	if(fread(buf, 1, sizeof(buf), b) == -1)
		return -1;
	*v = GETBE64(buf);
	return 0;
}

static int
readvint(char *p, char **pp)
{
	int i, n, c;

	i = 0;
	n = 0;
	do {
		c = *p++;
		n |= (c & 0x7f) << i;
		i += 7;
	} while (c & 0x80);
	*pp = p;

	return n;
}

static int
applydelta(Object *dst, Object *base, char *d, int nd)
{
	char *r, *b, *ed, *er;
	int n, nr, c;
	off_t o, l;

	ed = d + nd;
	b = base->data;
	n = readvint(d, &d);
	if(n != base->size){
		fprintf(stderr, "mismatched source size\n");
		return -1;
	}

	nr = readvint(d, &d);
	r = emalloc(nr + 64);
	n = snprintf(r, 64, "%s %d", typestr(base->type), nr) + 1;
	dst->all = r;
	dst->type = base->type;
	dst->data = r + n;
	dst->size = nr;
	er = dst->data + nr;
	r = dst->data;

	while(1){
		if(d == ed)
			break;
		c = *d++;
		if(!c){
			fprintf(stderr, "bad delta encoding\n");
			return -1;
		}
		/* copy from base */
		if(c & 0x80){
			o = 0;
			l = 0;
			/* Offset in base */
			if(c & 0x01 && d != ed) o |= (*d++ <<  0) & 0x000000ff;
			if(c & 0x02 && d != ed) o |= (*d++ <<  8) & 0x0000ff00;
			if(c & 0x04 && d != ed) o |= (*d++ << 16) & 0x00ff0000;
			if(c & 0x08 && d != ed) o |= (*d++ << 24) & 0xff000000;

			/* Length to copy */
			if(c & 0x10 && d != ed) l |= (*d++ <<  0) & 0x0000ff;
			if(c & 0x20 && d != ed) l |= (*d++ <<  8) & 0x00ff00;
			if(c & 0x40 && d != ed) l |= (*d++ << 16) & 0xff0000;
			if(l == 0) l = 0x10000;

			assert(o + l <= base->size);
			memmove(r, b + o, l);
			r += l;
		/* inline data */
		}else{
			memmove(r, d, c);
			d += c;
			r += c;
		}

	}
	if(r != er){
		fprintf(stderr, "truncated delta (%zd)\n", er - r);
		return -1;
	}

	return nr;
}

static int
readrdelta(FILE *f, Object *o, int nd, int flag)
{
	const struct got_error *e;
	struct got_object_id h;
	Object *b;
	uint8_t *d;
	size_t n;

	d = NULL;
	if(fread(h.sha1, 1, sizeof(h.sha1), f) != sizeof(h.sha1))
		goto error;
	if(hasheq(&o->hash, &h))
		goto error;
	if ((e = got_inflate_to_mem(&d, &n, NULL, f)) != NULL)
		goto error;
	o->len = ftello(f) - o->off;
	if(d == NULL || n != nd)
		goto error;
	if((b = readidxobject(f, h, flag)) == NULL)
		goto error;
	if(applydelta(o, b, d, n) == -1)
		goto error;
	free(d);
	return 0;
error:
	free(d);
	return -1;
}

static int
readodelta(FILE *f, Object *o, off_t nd, off_t p, int flag)
{
	Object b;
	uint8_t *d;
	off_t r;
	size_t n;
	int c;

	r = 0;
	d = NULL;
	while(1){
		if((c = fgetc(f)) == -1)
			goto error;
		r |= c & 0x7f;
		if (!(c & 0x80))
			break;
		r++;
		r <<= 7;
	}while(c & 0x80);

	if(r > p){
		fprintf(stderr, "junk offset -%lld (from %lld)\n", r, p);
		goto error;
	}

	if (got_inflate_to_mem(&d, &n, NULL, f) != NULL)
		goto error;
	o->len = ftello(f) - o->off;
	if(d == NULL || n != nd)
		goto error;
	if(fseek(f, p - r, SEEK_SET) == -1)
		goto error;
	if(readpacked(f, &b, flag) == -1)
		goto error;
	if(applydelta(o, &b, d, nd) == -1)
		goto error;
	free(d);
	return 0;
error:
	free(d);
	return -1;
}

static int
readpacked(FILE *f, Object *o, int flag)
{
	const struct got_error *e;
	int c, s, n;
	off_t l, p;
	size_t ndata;
	uint8_t *data;
	Type t;
	Buf b;

	p = ftello(f);
	c = fgetc(f);
	if(c == -1)
		return -1;
	l = c & 0xf;
	s = 4;
	t = (c >> 4) & 0x7;
	if(!t){
		fprintf(stderr, "unknown type for byte %x\n", c);
		return -1;
	}
	while(c & 0x80){
		if((c = fgetc(f)) == -1)
			return -1;
		l |= (c & 0x7f) << s;
		s += 7;
	}

	switch(t){
	default:
		fprintf(stderr, "invalid object at %lld\n", ftello(f));
		return -1;
	case GCommit:
	case GTree:
	case GTag:
	case GBlob:
		b.sz = 64 + l;

		b.data = emalloc(b.sz);
		n = snprintf(b.data, 64, "%s %lld", typestr(t), l) + 1;
		b.len = n;
		e = got_inflate_to_mem(&data, &ndata, NULL, f);
		if (e != NULL || n + ndata >= b.sz) {
			free(b.data);
			return -1;
		}
		memcpy(b.data + n, data, ndata);
		o->len = ftello(f) - o->off;
		o->type = t;
		o->all = b.data;
		o->data = b.data + n;
		o->size = ndata;
		free(data);
		break;
	case GOdelta:
		if(readodelta(f, o, l, p, flag) == -1)
			return -1;
		break;
	case GRdelta:
		if(readrdelta(f, o, l, flag) == -1)
			return -1;
		break;
	}
	o->flag |= Cloaded|flag;
	return 0;
}

static int
readloose(FILE *f, Object *o, int flag)
{
	struct { char *tag; int type; } *p, types[] = {
		{"blob", GBlob},
		{"tree", GTree},
		{"commit", GCommit},
		{"tag", GTag},
		{NULL},
	};
	char *s, *e;
	uint8_t *d;
	off_t sz;
	size_t n;
	int l;

	if (got_inflate_to_mem(&d, &n, NULL, f) != NULL)
		return -1;

	s = (char *)d;
	o->type = GNone;
	for(p = types; p->tag; p++){
		l = strlen(p->tag);
		if(strncmp(s, p->tag, l) == 0){
			s += l;
			o->type = p->type;
			while(!isspace(*s))
				s++;
			break;
		}
	}
	if(o->type == GNone){
		free(o->data);
		return -1;
	}
	sz = strtol(s, &e, 0);
	if(e == s || *e++ != 0){
		fprintf(stderr, "malformed object header\n");
		goto error;
	}
	if(sz != n - (e - (char *)d)){
		fprintf(stderr, "mismatched sizes\n");
		goto error;
	}
	o->size = sz;
	o->data = e;
	o->all = d;
	o->flag |= Cloaded|flag;
	return 0;

error:
	free(d);
	return -1;
}

static off_t
searchindex(FILE *f, struct got_object_id h)
{
	int lo, hi, idx, i, nent;
	off_t o, oo;
	struct got_object_id hh;

	o = 8;
	/*
	 * Read the fanout table. The fanout table
	 * contains 256 entries, corresponsding to
	 * the first byte of the hash. Each entry
	 * is a 4 byte big endian integer, containing
	 * the total number of entries with a leading
	 * byte <= the table index, allowing us to
	 * rapidly do a binary search on them.
	 */
	if (h.sha1[0] == 0){
		lo = 0;
		if(preadbe32(f, &hi, o) == -1)
			goto err;
	} else {
		o += h.sha1[0]*4 - 4;
		if(preadbe32(f, &lo, o + 0) == -1)
			goto err;
		if(preadbe32(f, &hi, o + 4) == -1)
			goto err;
	}
	if(hi == lo)
		goto notfound;
	if(preadbe32(f, &nent, 8 + 255*4) == -1)
		goto err;

	/*
	 * Now that we know the range of hashes that the
	 * entry may exist in, read them in so we can do
	 * a bsearch.
	 */
	idx = -1;
	fseek(f, Hashsz*lo + 8 + 256*4, SEEK_SET);
	for(i = 0; i < hi - lo; i++){
		if(fread(hh.sha1, 1, sizeof(hh.sha1), f) == -1)
			goto err;
		if(hasheq(&hh, &h))
			idx = lo + i;
	}
	if(idx == -1)
		goto notfound;


	/*
	 * We found the entry. If it's 32 bits, then we
	 * can just return the oset, otherwise the 32
	 * bit entry contains the oset to the 64 bit
	 * entry.
	 */
	oo = 8;			/* Header */
	oo += 256*4;		/* Fanout table */
	oo += Hashsz*nent;	/* Hashes */
	oo += 4*nent;		/* Checksums */
	oo += 4*idx;		/* Offset offset */
	if(preadbe32(f, &i, oo) == -1)
		goto err;
	o = i & 0xffffffff;
	if(o & (1ull << 31)){
		o &= 0x7fffffff;
		if(preadbe64(f, &o, o) == -1)
			goto err;
	}
	return o;

err:
	fprintf(stderr, "unable to read packfile\n");
	return -1;
notfound:
	{
		char hstr[41];
		hashfmt(hstr, sizeof(hstr), &h);
		fprintf(stdout, "could not find object %s\n", hstr);
	}
	return -1;
}

/*
 * Scans for non-empty word, copying it into buf.
 * Strips off word, leading, and trailing space
 * from input.
 *
 * Returns -1 on empty string or error, leaving
 * input unmodified.
 */
static int
scanword(char **str, int *nstr, char *buf, int nbuf)
{
	char *p;
	int n, r;

	r = -1;
	p = *str;
	n = *nstr;
	while(n && isblank(*p)){
		n--;
		p++;
	}

	for(; n && *p && !isspace(*p); p++, n--){
		r = 0;
		*buf++ = *p;
		nbuf--;
		if(nbuf == 0)
			return -1;
	}
	while(n && isblank(*p)){
		n--;
		p++;
	}
	*buf = 0;
	*str = p;
	*nstr = n;
	return r;
}

static void
nextline(char **str, int *nstr)
{
	char *s;

	if((s = strchr(*str, '\n')) != NULL){
		*nstr -= s - *str + 1;
		*str = s + 1;
	}
}

static int
parseauthor(char **str, int *nstr, char **name, off_t *time)
{
	return 0;
}

static void
parsecommit(Object *o)
{
	char *p, *t, buf[128];
	int np;

	p = o->data;
	np = o->size;
	o->commit = emalloc(sizeof(Cinfo));
	while(1){
		if(scanword(&p, &np, buf, sizeof(buf)) == -1)
			break;
		if(strcmp(buf, "tree") == 0){
			if(scanword(&p, &np, buf, sizeof(buf)) == -1)
				errx(1, "invalid commit: tree missing");
			if(hparse(&o->commit->tree, buf) == -1)
				errx(1, "invalid commit: garbled tree");
		}else if(strcmp(buf, "parent") == 0){
			if(scanword(&p, &np, buf, sizeof(buf)) == -1)
				errx(1, "invalid commit: missing parent");
			o->commit->parent = realloc(o->commit->parent, ++o->commit->nparent * sizeof(struct got_object_id));
			if(!o->commit->parent)
				err(1, "unable to malloc: ");
			if(hparse(&o->commit->parent[o->commit->nparent - 1], buf) == -1)
				errx(1, "invalid commit: garbled parent");
		}else if(strcmp(buf, "author") == 0){
			parseauthor(&p, &np, &o->commit->author, &o->commit->mtime);
		}else if(strcmp(buf, "committer") == 0){
			parseauthor(&p, &np, &o->commit->committer, &o->commit->ctime);
		}else if(strcmp(buf, "gpgsig") == 0){
			/* just drop it */
			if((t = strstr(p, "-----END PGP SIGNATURE-----")) == NULL)
				errx(1, "malformed gpg signature");
			np -= t - p;
			p = t;
		}
		nextline(&p, &np);
	}
	while (np && isspace(*p)) {
		p++;
		np--;
	}
	o->commit->msg = p;
	o->commit->nmsg = np;
}

static void
parsetree(Object *o)
{
	char *p, buf[256];
	int np, nn, m;
	Dirent *t;

	p = o->data;
	np = o->size;
	o->tree = emalloc(sizeof(Tinfo));
	while(np > 0){
		if(scanword(&p, &np, buf, sizeof(buf)) == -1)
			break;
		o->tree->ent = erealloc(o->tree->ent, ++o->tree->nent * sizeof(Dirent));
		t = &o->tree->ent[o->tree->nent - 1];
		memset(t, 0, sizeof(Dirent));
		m = strtol(buf, NULL, 8);
		/* FIXME: symlinks and other BS */
		if(m == 0160000){
			t->mode |= S_IFDIR;
			t->modref = 1;
		}
		t->mode = m & 0777;
		if(m & 0040000)
			t->mode |= S_IFDIR;
		t->name = p;
		nn = strlen(p) + 1;
		p += nn;
		np -= nn;
		if(np < sizeof(t->h.sha1))
			errx(1, "malformed tree, remaining %d (%s)", np, p);
		memcpy(t->h.sha1, p, sizeof(t->h.sha1));
		p += sizeof(t->h.sha1);
		np -= sizeof(t->h.sha1);
	}
}

void
parseobject(Object *o)
{
	if(o->flag & Cparsed)
		return;
	switch(o->type){
	case GTree:	parsetree(o);	break;
	case GCommit:	parsecommit(o);	break;
	//case GTag:	parsetag(o);	break;
	default:	break;
	}
	o->flag |= Cparsed;
}

static Object*
readidxobject(FILE *idx, struct got_object_id h, int flag)
{
	char path[Pathmax];
	char hbuf[41];
	FILE *f;
	Object *obj;
	int l, n;
	off_t o;
	struct dirent *ent;
	DIR *d;


	if ((obj = got_object_idset_lookup_data(objcache, &h))) {
		if(obj->flag & Cloaded)
			return obj;
		if(obj->flag & Cidx){
			assert(idx != NULL);
			o = ftello(idx);
			if(fseek(idx, obj->off, SEEK_SET) == -1)
				errx(1, "could not seek to object offset");
			if(readpacked(idx, obj, flag) == -1)
				errx(1, "could not reload object");
			if(fseek(idx, o, SEEK_SET) == -1)
				errx(1, "could not restore offset");
			cache(obj);
			return obj;
		}
	}

	d = NULL;
	/* We're not putting it in the cache yet... */
	obj = emalloc(sizeof(Object));
	obj->id = next_object_id + 1;
	obj->hash = h;

	hashfmt(hbuf, sizeof(hbuf), &h);
	snprintf(path, sizeof(path), ".git/objects/%c%c/%s", hbuf[0], hbuf[1], hbuf + 2);
	if((f = fopen(path, "r")) != NULL){
		if(readloose(f, obj, flag) == -1)
			goto error;
		fclose(f);
		parseobject(obj);
		hashfmt(hbuf, sizeof(hbuf), &obj->hash);
		fprintf(stderr, "object %s cached\n", hbuf);
		cache(obj);
		return obj;
	}

	o = -1;
	if ((d = opendir(".git/objects/pack")) == NULL)
		err(1, "open pack dir");
	while ((ent = readdir(d)) != NULL) {
		l = strlen(ent->d_name);
		if(l > 4 && strcmp(ent->d_name + l - 4, ".idx") != 0)
			continue;
		snprintf(path, sizeof(path), ".git/objects/pack/%s", ent->d_name);
		if((f = fopen(path, "r")) == NULL)
			continue;
		o = searchindex(f, h);
		fclose(f);
		if(o == -1)
			continue;
		break;
	}
	closedir(d);

	if (o == -1)
		goto error;

	if((n = snprintf(path, sizeof(path), "%s", path)) >= sizeof(path) - 4)
		goto error;
	memcpy(path + n - 4, ".pack", 6);
	if((f = fopen(path, "r")) == NULL)
		goto error;
	if(fseek(f, o, SEEK_SET) == -1)
		goto error;
	if(readpacked(f, obj, flag) == -1)
		goto error;
	fclose(f);
	parseobject(obj);
	cache(obj);
	return obj;
error:
	free(obj);
	return NULL;
}

Object*
readobject(struct got_object_id h)
{
	Object *o;

	o = readidxobject(NULL, h, 0);
	if(o)
		ref(o);
	return o;
}

int
objcmp(const void *pa, const void *pb)
{
	Object *a, *b;

	a = *(Object**)pa;
	b = *(Object**)pb;
	return memcmp(a->hash.sha1, b->hash.sha1, sizeof(a->hash.sha1));
}

static int
hwrite(FILE *b, void *buf, int len, SHA1_CTX *ctx)
{
	SHA1Update(ctx, buf, len);
	return fwrite(buf, 1, len, b);
}

static uint32_t
objectcrc(FILE *f, Object *o)
{
	char buf[8096];
	int n, r;

	o->crc = 0;
	fseek(f, o->off, SEEK_SET);
	for(n = o->len; n > 0; n -= r){
		r = fread(buf, 1, n > sizeof(buf) ? sizeof(buf) : n, f);
		if(r == -1)
			return -1;
		if(r == 0)
			return 0;
		o->crc = crc32(o->crc, buf, r);
	}
	return 0;
}

int
indexpack(int packfd, int idxfd, struct got_object_id *packhash)
{
	char hdr[4*3], buf[8];
	int nobj, nvalid, nbig, n, i, step;
	Object *o, **objects;
	char *valid;
	SHA1_CTX ctx, objctx;
	FILE *f;
	struct got_object_id h;
	int c;

	if ((f = fdopen(packfd, "r")) == NULL)
		return -1;
	if (fseek(f, 0, SEEK_SET) == -1)
		return -1;
	if (fread(hdr, 1, sizeof(hdr), f) != sizeof(hdr)) {
		fprintf(stderr, "short read on header\n");
		return -1;
	}
	if (memcmp(hdr, "PACK\0\0\0\2", 8) != 0) {
		fprintf(stderr, "invalid header\n");
		return -1;
	}

	nvalid = 0;
	nobj = GETBE32(hdr + 8);
	objects = calloc(nobj, sizeof(Object*));
	valid = calloc(nobj, sizeof(char));
	step = nobj/100;
	if(!step)
		step++;
	while (nvalid != nobj) {
		fprintf(stderr, "indexing (%d/%d):", nvalid, nobj);
		n = 0;
		for (i = 0; i < nobj; i++) {
			if (valid[i]) {
				n++;
				continue;
			}
			if (i % step == 0)
				fprintf(stderr, ".");
			if (!objects[i]) {
				o = emalloc(sizeof(Object));
				o->off = ftello(f);
				objects[i] = o;
			}
			o = objects[i];
			fseek(f, o->off, SEEK_SET);
			if (readpacked(f, o, Cidx) == 0){
				SHA1Init(&objctx);
				SHA1Update(&objctx, (uint8_t*)o->all, o->size + strlen(o->all) + 1);
				SHA1Final(o->hash.sha1, &objctx);
				cache(o);
				valid[i] = 1;
				n++;
			}
			if(objectcrc(f, o) == -1)
				return -1;
		}
		fprintf(stderr, "\n");
		if (n == nvalid) {
			errx(1, "fix point reached too early: %d/%d", nvalid, nobj);
			goto error;
		}
		nvalid = n;
	}
	fclose(f);

	SHA1Init(&ctx);
	qsort(objects, nobj, sizeof(Object*), objcmp);
	if((f = fdopen(idxfd, "w")) == NULL)
		return -1;
	if(hwrite(f, "\xfftOc\x00\x00\x00\x02", 8, &ctx) != 8)
		goto error;
	/* fanout table */
	c = 0;
	for(i = 0; i < 256; i++){
		while(c < nobj && (objects[c]->hash.sha1[0] & 0xff) <= i)
			c++;
		PUTBE32(buf, c);
		hwrite(f, buf, 4, &ctx);
	}
	for(i = 0; i < nobj; i++){
		o = objects[i];
		hwrite(f, o->hash.sha1, sizeof(o->hash.sha1), &ctx);
	}

	/* pointless, nothing uses this */
	for(i = 0; i < nobj; i++){
		PUTBE32(buf, objects[i]->crc);
		hwrite(f, buf, 4, &ctx);
	}

	nbig = 0;
	for(i = 0; i < nobj; i++){
		if(objects[i]->off <= (1ull<<31))
			PUTBE32(buf, objects[i]->off);
		else
			PUTBE32(buf, (1ull << 31) | nbig++);
		hwrite(f, buf, 4, &ctx);
	}
	for(i = 0; i < nobj; i++){
		if(objects[i]->off > (1ull<<31)){
			PUTBE64(buf, objects[i]->off);
			hwrite(f, buf, 8, &ctx);
		}
	}
	hwrite(f, packhash->sha1, sizeof(packhash->sha1), &ctx);
	SHA1Final(h.sha1, &ctx);
	fwrite(h.sha1, 1, sizeof(h.sha1), f);

	free(objects);
	free(valid);
	fclose(f);
	return 0;

error:
	free(objects);
	free(valid);
	fclose(f);
	return -1;
}

int
main(int argc, char **argv)
{
	const struct got_error *err = NULL;
	struct got_object_id packhash;
	struct imsgbuf ibuf;
	struct imsg imsg;
	int packfd, idxfd;

	objcache = got_object_idset_alloc();
	imsg_init(&ibuf, GOT_IMSG_FD_CHILD);
	if((err = got_privsep_recv_imsg(&imsg, &ibuf, 0)) != 0) {
		if (err->code == GOT_ERR_PRIVSEP_PIPE)
			err = NULL;
		goto done;
	}
	if (imsg.hdr.type == GOT_IMSG_STOP)
		goto done;
	if (imsg.hdr.type != GOT_IMSG_IDXPACK_REQUEST) {
		err = got_error(GOT_ERR_PRIVSEP_MSG);
		goto done;
	}
	if (imsg.hdr.len - IMSG_HEADER_SIZE != SHA1_DIGEST_LENGTH) {
		err = got_error(GOT_ERR_PRIVSEP_LEN);
		goto done;
	}
	packfd = imsg.fd;
	memcpy(packhash.sha1, imsg.data, SHA1_DIGEST_LENGTH);

	if((err = got_privsep_recv_imsg(&imsg, &ibuf, 0)) != 0) {
		if (err->code == GOT_ERR_PRIVSEP_PIPE)
			err = NULL;
		goto done;
	}
	if (imsg.hdr.type == GOT_IMSG_STOP)
		goto done;
	if (imsg.hdr.type != GOT_IMSG_TMPFD) {
		err = got_error(GOT_ERR_PRIVSEP_MSG);
		goto done;
	}
	if (imsg.hdr.len - IMSG_HEADER_SIZE != 0) {
		err = got_error(GOT_ERR_PRIVSEP_LEN);
		goto done;
	}
	idxfd = imsg.fd;

	indexpack(packfd, idxfd, &packhash);
done:
	if(err != NULL)
		got_privsep_send_error(&ibuf, err);
	else
		err = got_privsep_send_index_pack_done(&ibuf);
	if(err != NULL) {
		fprintf(stderr, "%s: %s\n", getprogname(), err->msg);
		got_privsep_send_error(&ibuf, err);
	}

	exit(0);
}
