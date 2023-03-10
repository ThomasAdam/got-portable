#!/usr/bin/env bash
#
# Script to sync changes from upstream to -portable
#
# This script is under the same licence as gameoftrees itself.

PORTABLE_BRANCH="portable"

die()
{
	echo "$@" >&2
	exit 1
}

# Wrap the nproc command found on Linux, to return the number of CPU cores.
# On non-Linux systems, the same value can be found via sysctl.  For
# everything else, just return "1".
nproc()
{
	NPROCCMD="nproc"

	command "$NPROCCMD" >/dev/null 2>&1 || {
		NPROCCMD="sysctl -n hw.ncpu"
	}

	result="$(eval command $NPROCCMD)"
	[ -z "$result" -o "$result" -le 0 ] && result="1"

	echo "$result"
}

[ -z "$(git status --porcelain)" ] || die "Working tree is not clean"

echo "Updating main from origin..."

# Update our copy of main 
git checkout -q main && \
git fetch -q -n gh >/dev/null 2>&1
git fetch -q -n upstream >/dev/null 2>&1 && \
git reset -q --hard upstream/main || {
	die "Couldn't fetch from main and reset to that branch"
}

# Gather a list of commits to cherry-pick.
# Don't proceed with no commits.
commitc="$(git rev-list --count main...origin/main)"
[ -z "$commitc" -o "$commitc" -eq 0 ] && {
	echo "All commits uptodate.  Nothing to cherry-pick"
	exit
}

# Create a branch from $PORTABLE_BRANCH (which is where the result of the
# cherry-picks will ultimately end up, but we do this work on a topic branch
# so that we can perform CI on it, and not break the $PORTABLE_BRANCH branch.

echo "Creating sync branch..."
git branch -q -D syncup >/dev/null 2>&1
git checkout -q "$PORTABLE_BRANCH" && git checkout -q -b syncup || {
	die "Can't checkout syncup branch"
}

echo "The following ($commitc) commits will be cherry-picked..."
git log --oneline main...origin/main

read -p "Proceed? [Y/n]: " resp

[ "$resp" = "N" -o "$resp" = "n" ] && exit

# Pick the commits in reverse order.
git rev-list --reverse --first-parent main...origin/main | \
	git cherry-pick --stdin --no-rerere-autoupdate -Xtheirs

[ $? -eq 0 ] && {
	# Sanity-check header files which are found portably and remove them.
	for h in 'sys\/queue.h' 'ssl\.h' 'endian\.h'
	do
		# Use git's pathspec notation to exclude matching on files
		# where we *want* to keep those headers.
		git grep -Li "$h" -- \
			':!maintscripts/**' \
			':!configure.ac' \
			':!gotweb/parse.y' \
			':!include/got_compat.h' | \
			while read file
			do
				sed -i -e "/$h/d" "$file"
			done
	done

	echo "Performing sanity build..."
	./autogen.sh >/dev/null 2>&1 && \
	./configure >/dev/null 2>&1  && \
	make -j $(nproc) >/dev/null 2>&1 && {
		echo "   Passed!"
		echo "Creating commit for portable changes..."
		git commit -am "portable: remove include files found portably"
		echo "...Merging branch to $PORTABLE_BRANCH"
		git checkout "$PORTABLE_BRANCH" && git merge --ff-only - && {
			echo "Pushing to GH..."
			git push gh || die "Couldn't push $PORTABLE_BRANCH to GH"
			git checkout main && \
			git push gh || die "Couldn't push main to GH"
		}
	} || die "Build failed"
}

echo "Wait for Cirrus-CI..."
echo "Then push main and $PORTABLE_BRANCH to origin"
