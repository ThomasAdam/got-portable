#!/bin/bash
#
# Script to sync changes from upstream to -portable
#
# This script is under the same licence as gameoftrees itself.

die()
{
	echo "$@" >&2
	exit 1
}

[ -z "$(git status --porcelain)" ] || die "Working tree is not clean"

echo "Updating main from origin..."

# Update our copy of main 
git checkout -q main && \
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

# Create a branch from linux (which is where the result of the cherry-picks
# will ultimately end up, but we do this work on a topic branch so that we can
# perform CI on it, and not break the 'linux' branch.

echo "Creating sync branch..."
git branch -q -D syncup >/dev/null 2>&1
git checkout -q linux && git checkout -q -b syncup || {
	die "Can't checkout syncup branch"
}

echo "The following ($commitc) commits will be cherry-picked..."
git log --oneline main...origin/main

read -p "Proceed? [Y/n]: " resp

[ "$resp" = "N" -o "$resp" = "n" ] && exit

git cherry-pick --no-rerere-autoupdate -Xtheirs \
	$(git rev-list --first-parent main...origin/main)

[ $? -eq 0 ] && {
	echo "Performing sanity build..."
	./autogen.sh >/dev/null 2>&1 && \
	./configure >/dev/null 2>&1  && \
	make -j $(nproc) >/dev/null 2>&1 && {
		echo "   Passed!"
		echo "...Merging branch to linux"
		git checkout linux && git merge --ff-only - && {
			echo "Pushing to GH..."
			git push gh || die "Couldn't push linux to GH"
			git checkout main && \
			git push gh || die "Couldn't push main to GH"
		}
	} || die "Build failed"
}

echo "Wait for Cirrus-CI..."
echo "Then push main and linux to origin"
