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
* `GNU coreutils` (for running tests)

NetBSD:

* `automake`
* `libuuid`
* `ncuresesw`
* `GNU coreutils` (for running tests)

DragonFlyBSD:

* `automake`
* `pkgconf`
* `openssl`
* `GNU coreutils` (for running tests)

Darwin (MacOS):

* `automake`
* `bison`
* `pkg-config`
* `ncurses`
* `openssl`
* `ossp-uuid`

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

TODO
====

This port is incomplete in that only got(1) and tog(1) have been ported.
gotweb has yet to be ported.

configure.ac should start defining AC_ENABLE arguments to allow for
finer-grained control of where to search for includes/libraries, etc.

CONTACT
=======

Thomas Adam <thomas@xteddy.org>
thomas_adam (#gameoftrees on irc.libera.chat)

[1]  https://gameoftrees.org
[2]  https://lists.openbsd.org/cgi-bin/mj_wwwusr?user=&passw=&func=lists-long-full&extra=gameoftrees
