README.portable
===============

**NOTE: This repository is read-only and is used only to mirror the
got-portable repository for CI purposes.**

This is the portable version of got[1] (Game of Trees), using autotools to
provide the library checks required for GoT's dependencies.

The following operating systems are supported:

* FreeBSD
* NetBSD
* DragonFlyBSD
* MacOS
* Linux

DEPENDENCIES
============

Linux:

* `libncurses` (for tog(1))
* `libmd` (BSD's digest routines)
* `libbsd` (BSD's arc4random routines)
* `libcrypto` (often via 'libssl-dev' for SHA1 routines)
* `libuuid` (for UUID generation)
* `libz` (for Z compression)
* `pkg-config` (for searching libraries)
* `bison` (for configuration file grammar)

FreeBSD:

* `automake`
* `pkgconf`
* `libevent` (for gotwebd)

NetBSD:

* `automake`
* `libuuid`
* `ncuresesw`
* `libevent` (for gotwebd)

DragonFlyBSD:

* `automake`
* `pkgconf`
* `openssl`
* `libevent` (for gotwebd)

Darwin (MacOS):

* `automake`
* `bison`
* `pkg-config`
* `ncurses`
* `openssl`
* `ossp-uuid`
* `libevent` (for gotwebd)

TESTS (REGRESS)
===============

To run the test suite:

```
 $ make tests
```

NOTE: For Linux, you must have the jot(1) command which is typically in the
`athena-jot` package, or similar.  For non-linux systems (as mentioned above),
GNU Coreutils needs to be installed.

NOTE:  THIS ONLY WORKS AFTER `make install` DUE TO HOW PATHS TO LIBEXEC
       HELPERS ARE HARD-CODED INTO THE BINARIES.

INSTALLATION
============

```
 $ ./autogen.sh
 $ ./configure && make
 $ sudo make install
```

BRANCHES + SUBMITTING PATCHES
=============================

`got-portable` has two key branches:

* `main` which tracks got upstream untainted.
* `linux` which provides the portable version of GoT based from code on `main`

Patches for portable code fixes should be based from the `linux` branch and
sent to the mailing list for review [2] or sent to me directly (see CONTACT).

Portable-specific patches should have a shortlog in the form of:

```
portable: AREA: description
```

Where `AREA` relates to the change in question (for example, `regress`,
`libexec`, etc).  In some cases, this can be omitted if it's a generic change.

This helps to delineate `-portable` changes from upstream `got`.

The read-only Github repository also runs CI checks using Cirrus-CI on Linux
and FreeBSD.

SYNCING UPSTREAM CHANGES WITH PORTABLE
======================================

The `-portable` GoT repository uses the following workflow:

```
                Github (gh)               GoT (upstream)
		  ^                              ^
		  |                              |
		  |                              |
		  |                              |
		  |                              |
		  +--------> GoT-portable <------+

```

Here, `got-portable` is a clone of the `-portable` repository, locally on
disk.  There are two remotes set up within that repository, via `git-remote`:

* `upstream` -- which points to the official GoT repository;
* `gh` -- which points to the mirrored `-portable` repository so that CI can
  be run for cross-platform/test purposes [3]
* `origin` -- our cloned copy from `-portable`

Within the `-portable` repository are two key branches (there may be other
topic branches which represent on-going work):

* `main` -- this is the branch that tracks (without modification) those
  changes from `upstream`.  This branch is continually reset to
  `upstream/main` whenever changes occur.

* `linux` -- this is the *default* branch of the `-portable` repository which
  contains portable-specific changes to make `GoT` compile across different
  OSes.

When updating `-portable` from upstream changes, the following actions happen:

1. Changes from `upstream` are fetched.  If there are no new changes, there's
   nothing else to do.
2. Changes from `gh` are fetch so that the result can be pushed out to `gh`.
3. The difference between the local copy of `main` and `origin/main` is used
   to represent the set of commits which have *NOT* yet been merged to
   `-portable`.
4. A topic-branch called `syncup` is created from the HEAD of the `linux`
   branch to hold the to-be-cherry-picked commits from step 3.
5. These commits are then cherry-picked to the `syncup` branch.
6. If there's any conflicts, they must be resolved.
7. Once done, a sanity build is done in-situ to check there's nothing amiss.
8. If that succeeds, the `syncup` branch is merged to `linux` and pushed to
   `gh` for verification against CI.
9. If that fails, fixes continue and pushed up to `gh` as required.
10. Once happy, both the `main` and `linux` branches can be merged to `origin`.

These steps are encapsulated in a script within `-portable`.  [Link](../maintscripts/sync-upstream.sh)

RELEASING A NEW VERSION
=======================

Release for `-portable` try and align as close to upstream GoT as much as
possible, even on the same day where that can happen.  That being said,
sometimes a release of `-portable` might happen outside of that cadence, where
a `-portable`-specific issue needs addressing, for example.

Before creating a new release, check the version of GoT as found in
`util/got-portable-ver.sh` -- as `GOT_PORTABLE_VER`:

```
GOT_PORTABLE_VER=0.75

```

Here, the *to be released* version of `got-portable` will be `0.75`.
Typically, this version is incremented directly after a release, such that
there's no need to change this value.  The only exception would be if there
were an out-of-band release to `-portable`.  In such cases, that would take
the form:

```
0.75.1
```

Where the suffix of `1`, `2`, etc., can be used to denote any sub-releases
from the `0.75` version.

The variable `GOT_RELEASE` needs be changed to `yes` so that the
GOT_PORTABLE_VER is asserted correctly.

Once the version is verified, the following should be run from the `linux`
branch -- and the repository should not have any outstanding modifications to
the source:

```
make clean ; ./autogen && ./configure && make distcheck
```

If this succeeds, the tarball is in the CWD, as: `got-portable-VERSION.tar.gz`

This can then be copied to the `got-www` repository and uploaded, along with
changing a couple of HTML pages therein to represent the new released version.
Additionally, the CHANGELOG file can be copied to the `got-www` and committed.

Once all of that has been done, the repository should be tagged to indicate
the release, hence:

```
git tag -a 0.75
```

This can then be pushed out to `gh` and `origin`.

After that point, the version of `GOT_PORTABLE_VER` in
`util/got-portable-ver.sh` should be changed to the next version, and
`GOT_RELEASE` should be setg back to `no`.

TODO
====

This port is incomplete in that only got(1) and tog(1) have been ported.
gotweb has yet to be ported.

configure.ac should start defining AC_ENABLE arguments to allow for
finer-grained control of where to search for includes/libraries, etc.

CONTACT
=======

Thomas Adam <thomas@xteddy.org><br />
thomas_adam (#gameoftrees on irc.libera.chat)

[1]  https://gameoftrees.org<br />
[2]  https://lists.openbsd.org/cgi-bin/mj_wwwusr?user=&passw=&func=lists-long-full&extra=gameoftrees<br />
[3]  https://github.com/ThomasAdam/got-portable
