/* Implementation of the Patience Diff algorithm invented by Bram Cohen:
 * Divide a diff problem into smaller chunks by an LCS (Longest Common Sequence)
 * of common-unique lines. */
/*
 * Copyright (c) 2020 Neels Hofmeyr <neels@hofmeyr.de>
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

#include <assert.h>
#include <inttypes.h>
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

#include <arraylist.h>
#include <diff_main.h>

#include "diff_internal.h"
#include "diff_debug.h"

/* Algorithm to find unique lines:
 * 0: stupidly iterate atoms
 * 1: qsort
 * 2: mergesort
 */
#define UNIQUE_STRATEGY 1

/* Per-atom state for the Patience Diff algorithm */
struct atom_patience {
#if UNIQUE_STRATEGY == 0
	bool unique_here;
#endif
	bool unique_in_both;
	struct diff_atom *pos_in_other;
	struct diff_atom *prev_stack;
	struct diff_range identical_lines;
};

/* A diff_atom has a backpointer to the root diff_data. That points to the
 * current diff_data, a possibly smaller section of the root. That current
 * diff_data->algo_data is a pointer to an array of struct atom_patience. The
 * atom's index in current diff_data gives the index in the atom_patience array.
 */
#define PATIENCE(ATOM) \
	(((struct atom_patience*)((ATOM)->root->current->algo_data))\
	 [diff_atom_idx((ATOM)->root->current, ATOM)])

#if UNIQUE_STRATEGY == 0

/* Stupid iteration and comparison of all atoms */
static int
diff_atoms_mark_unique(struct diff_data *d, unsigned int *unique_count)
{
	struct diff_atom *i;
	unsigned int count = 0;
	diff_data_foreach_atom(i, d) {
		PATIENCE(i).unique_here = true;
		PATIENCE(i).unique_in_both = true;
		count++;
	}
	diff_data_foreach_atom(i, d) {
		struct diff_atom *j;

		if (!PATIENCE(i).unique_here)
			continue;

		diff_data_foreach_atom_from(i + 1, j, d) {
			bool same;
			int r = diff_atom_same(&same, i, j);
			if (r)
				return r;
			if (!same)
				continue;
			if (PATIENCE(i).unique_here) {
				PATIENCE(i).unique_here = false;
				PATIENCE(i).unique_in_both = false;
				count--;
			}
			PATIENCE(j).unique_here = false;
			PATIENCE(j).unique_in_both = false;
			count--;
		}
	}
	if (unique_count)
		*unique_count = count;
	return 0;
}

/* Mark those lines as PATIENCE(atom).unique_in_both = true that appear exactly
 * once in each side. */
static int
diff_atoms_mark_unique_in_both(struct diff_data *left, struct diff_data *right,
			       unsigned int *unique_in_both_count)
{
	/* Derive the final unique_in_both count without needing an explicit
	 * iteration. So this is just some optimiziation to save one iteration
	 * in the end. */
	unsigned int unique_in_both;
	int r;

	r = diff_atoms_mark_unique(left, &unique_in_both);
	if (r)
		return r;
	r = diff_atoms_mark_unique(right, NULL);
	if (r)
		return r;

	debug("unique_in_both %u\n", unique_in_both);

	struct diff_atom *i;
	diff_data_foreach_atom(i, left) {
		if (!PATIENCE(i).unique_here)
			continue;
		struct diff_atom *j;
		int found_in_b = 0;
		diff_data_foreach_atom(j, right) {
			bool same;
			int r = diff_atom_same(&same, i, j);
			if (r)
				return r;
			if (!same)
				continue;
			if (!PATIENCE(j).unique_here) {
				found_in_b = 2; /* or more */
				break;
			} else {
				found_in_b = 1;
				PATIENCE(j).pos_in_other = i;
				PATIENCE(i).pos_in_other = j;
			}
		}

		if (found_in_b == 0 || found_in_b > 1) {
			PATIENCE(i).unique_in_both = false;
			unique_in_both--;
			debug("unique_in_both %u  (%d) ", unique_in_both,
			      found_in_b);
			debug_dump_atom(left, NULL, i);
		}
	}

	/* Still need to unmark right[*]->patience.unique_in_both for atoms that
	 * don't exist in left */
	diff_data_foreach_atom(i, right) {
		if (!PATIENCE(i).unique_here
		    || !PATIENCE(i).unique_in_both)
			continue;
		struct diff_atom *j;
		bool found_in_a = false;
		diff_data_foreach_atom(j, left) {
			bool same;
			int r;
			if (!PATIENCE(j).unique_in_both)
				continue;
			r = diff_atom_same(&same, i, j);
			if (r)
				return r;
			if (!same)
				continue;
			found_in_a = true;
			break;
		}

		if (!found_in_a)
			PATIENCE(i).unique_in_both = false;
	}

	if (unique_in_both_count)
		*unique_in_both_count = unique_in_both;
	return 0;
}

#else /* UNIQUE_STRATEGY != 0 */

/* Use an optimized sorting algorithm (qsort, mergesort) to find unique lines */

int diff_atoms_compar(const void *_a, const void *_b)
{
	const struct diff_atom *a = *(struct diff_atom**)_a;
	const struct diff_atom *b = *(struct diff_atom**)_b;
	int cmp;
	int rc = 0;

	/* If there's been an error (e.g. I/O error) in a previous compar, we
	 * have no way to abort the sort but just report the rc and stop
	 * comparing. Make sure to catch errors on either side. If atoms are
	 * from more than one diff_data, make sure the error, if any, spreads
	 * to all of them, so we can cut short all future comparisons. */
	if (a->root->err)
		rc = a->root->err;
	if (b->root->err)
		rc = b->root->err;
	if (rc) {
		a->root->err = rc;
		b->root->err = rc;
		/* just return 'equal' to not swap more positions */
		return 0;
	}

	/* Sort by the simplistic hash */
	if (a->hash < b->hash)
		return -1;
	if (a->hash > b->hash)
		return 1;

	/* If hashes are the same, the lines may still differ. Do a full cmp. */
	rc = diff_atom_cmp(&cmp, a, b);

	if (rc) {
		/* Mark the I/O error so that the caller can find out about it.
		 * For the case atoms are from more than one diff_data, mark in
		 * both. */
		a->root->err = rc;
		if (a->root != b->root)
			b->root->err = rc;
		return 0;
	}

	return cmp;
}

/* Sort an array of struct diff_atom* in-place. */
static int diff_atoms_sort(struct diff_atom *atoms[],
			   size_t atoms_count)
{
#if UNIQUE_STRATEGY == 1
	qsort(atoms, atoms_count, sizeof(struct diff_atom*), diff_atoms_compar);
#else
	mergesort(atoms, atoms_count, sizeof(struct diff_atom*),
		  diff_atoms_compar);
#endif
	return atoms[0]->root->err;
}

static int
diff_atoms_mark_unique_in_both(struct diff_data *left, struct diff_data *right,
			       unsigned int *unique_in_both_count_p)
{
	struct diff_atom *a;
	struct diff_atom *b;
	struct diff_atom **all_atoms;
	unsigned int len = 0;
	unsigned int i;
	unsigned int unique_in_both_count = 0;
	int rc;

	all_atoms = calloc(left->atoms.len + right->atoms.len,
	    sizeof(struct diff_atom *));
	if (all_atoms == NULL)
		return ENOMEM;

	left->err = 0;
	right->err = 0;
	left->root->err = 0;
	right->root->err = 0;
	diff_data_foreach_atom(a, left) {
		all_atoms[len++] = a;
	}
	diff_data_foreach_atom(b, right) {
		all_atoms[len++] = b;
	}

	rc = diff_atoms_sort(all_atoms, len);
	if (rc)
		goto free_and_exit;

	/* Now we have a sorted array of atom pointers. All similar lines are
	 * adjacent. Walk through the array and mark those that are unique on
	 * each side, but exist once in both sources. */
	for (i = 0; i < len; i++) {
		bool same;
		unsigned int next_differing_i;
		unsigned int last_identical_i;
		unsigned int j;
		unsigned int count_first_side = 1;
		unsigned int count_other_side = 0;
		a = all_atoms[i];
		debug("a: ");
		debug_dump_atom(a->root, NULL, a);

		/* Do as few diff_atom_cmp() as possible: first walk forward
		 * only using the cheap hash as indicator for differing atoms;
		 * then walk backwards until hitting an identical atom. */
		for (next_differing_i = i + 1; next_differing_i < len;
		     next_differing_i++) {
			b = all_atoms[next_differing_i];
			if (a->hash != b->hash)
				break;
		}
		for (last_identical_i = next_differing_i - 1;
		     last_identical_i > i;
		     last_identical_i--) {
			b = all_atoms[last_identical_i];
			rc = diff_atom_same(&same, a, b);
			if (rc)
				goto free_and_exit;
			if (same)
				break;
		}
		next_differing_i = last_identical_i + 1;

		for (j = i+1; j < next_differing_i; j++) {
			b = all_atoms[j];
			/* A following atom is the same. See on which side the
			 * repetition counts. */
			if (a->root == b->root)
				count_first_side ++;
			else
				count_other_side ++;
			debug("b: ");
			debug_dump_atom(b->root, NULL, b);
			debug("   count_first_side=%d count_other_side=%d\n",
			      count_first_side, count_other_side);
		}

		/* Counted a section of similar atoms, put the results back to
		 * the atoms. */
		if ((count_first_side == 1)
		    && (count_other_side == 1)) {
			b = all_atoms[i+1];
			PATIENCE(a).unique_in_both = true;
			PATIENCE(a).pos_in_other = b;
			PATIENCE(b).unique_in_both = true;
			PATIENCE(b).pos_in_other = a;
			unique_in_both_count++;
		}

		/* j now points at the first atom after 'a' that is not
		 * identical to 'a'. j is always > i. */
		i = j - 1;
	}
	*unique_in_both_count_p = unique_in_both_count;
	rc = 0;
free_and_exit:
	free(all_atoms);
	return rc;
}
#endif /* UNIQUE_STRATEGY != 0 */

static int
diff_atoms_swallow_identical_neighbors(struct diff_data *left,
				       struct diff_data *right,
				       unsigned int *unique_in_both_count)
{
	debug("trivially combine identical lines"
	      " around unique_in_both lines\n");

	unsigned int l_idx;
	unsigned int next_l_idx;
	/* Only checking against identical-line overlaps on the left; overlaps
	 * on the right are tolerated and ironed out later. See also the other
	 * place marked with (1). */
	unsigned int l_min = 0;
	for (l_idx = 0; l_idx < left->atoms.len; l_idx = next_l_idx) {
		next_l_idx = l_idx + 1;
		struct diff_atom *l = &left->atoms.head[l_idx];
		struct diff_atom *r;

		if (!PATIENCE(l).unique_in_both)
			continue;

		debug("check identical lines around\n");
		debug(" L "); debug_dump_atom(left, right, l);

		unsigned int r_idx = diff_atom_idx(right, PATIENCE(l).pos_in_other);
		r = &right->atoms.head[r_idx];
		debug(" R "); debug_dump_atom(right, left, r);

		struct diff_range identical_l;
		struct diff_range identical_r;

		/* Swallow upwards.
		 * Each common-unique line swallows identical lines upwards and
		 * downwards.
		 * Will never hit another identical common-unique line above on
		 * the left, because those would already have swallowed this
		 * common-unique line in a previous iteration.
		 */
		for (identical_l.start = l_idx, identical_r.start = r_idx;
		     identical_l.start > (l_min+1) && identical_r.start > 0;
		     identical_l.start--, identical_r.start--) {
			bool same;
			int rc = diff_atom_same(&same,
				&left->atoms.head[identical_l.start - 1],
				&right->atoms.head[identical_r.start - 1]);
			if (rc)
				return rc;
			if (!same)
				break;
		}

		/* Swallow downwards. Join any common-unique lines in a block of
		 * matching L/R lines with this one. */
		for (identical_l.end = l_idx + 1, identical_r.end = r_idx + 1;
		     identical_l.end < left->atoms.len
			 && identical_r.end < right->atoms.len;
		     identical_l.end++, identical_r.end++,
		     next_l_idx++) {
			struct diff_atom *l_end;
			struct diff_atom *r_end;
			bool same;
			int rc = diff_atom_same(&same,
					&left->atoms.head[identical_l.end],
					&right->atoms.head[identical_r.end]);
			if (rc)
				return rc;
			if (!same)
				break;
			l_end = &left->atoms.head[identical_l.end];
			r_end = &right->atoms.head[identical_r.end];
			if (!PATIENCE(l_end).unique_in_both)
				continue;
			/* A unique_in_both atom is joined with a preceding
			 * unique_in_both atom, remove the joined atom from
			 * listing of unique_in_both atoms */
			PATIENCE(l_end).unique_in_both = false;
			PATIENCE(r_end).unique_in_both = false;
			(*unique_in_both_count)--;
		}

		PATIENCE(l).identical_lines = identical_l;
		PATIENCE(r).identical_lines = identical_r;

		l_min = identical_l.end;

		if (!diff_range_empty(&PATIENCE(l).identical_lines)) {
			debug("common-unique line at l=%u r=%u swallowed"
			      " identical lines l=%u-%u r=%u-%u\n",
			      l_idx, r_idx,
			      identical_l.start, identical_l.end,
			      identical_r.start, identical_r.end);
		}
		debug("next_l_idx = %u\n", next_l_idx);
	}
	return 0;
}

/* binary search to find the stack to put this atom "card" on. */
static int
find_target_stack(struct diff_atom *atom,
		  struct diff_atom **patience_stacks,
		  unsigned int patience_stacks_count)
{
	unsigned int lo = 0;
	unsigned int hi = patience_stacks_count;
	while (lo < hi) {
		unsigned int mid = (lo + hi) >> 1;

		if (PATIENCE(patience_stacks[mid]).pos_in_other
		    < PATIENCE(atom).pos_in_other)
			lo = mid + 1;
		else
			hi = mid;
	}
	return lo;
}

/* Among the lines that appear exactly once in each side, find the longest
 * streak that appear in both files in the same order (with other stuff allowed
 * to interleave). Use patience sort for that, as in the Patience Diff
 * algorithm.
 * See https://bramcohen.livejournal.com/73318.html and, for a much more
 * detailed explanation,
 * https://blog.jcoglan.com/2017/09/19/the-patience-diff-algorithm/ */
int
diff_algo_patience(const struct diff_algo_config *algo_config,
		   struct diff_state *state)
{
	int rc;
	struct diff_data *left = &state->left;
	struct diff_data *right = &state->right;
	struct atom_patience *atom_patience_left =
		calloc(left->atoms.len, sizeof(struct atom_patience));
	struct atom_patience *atom_patience_right =
		calloc(right->atoms.len, sizeof(struct atom_patience));
	unsigned int unique_in_both_count;
	struct diff_atom **lcs = NULL;

	debug("\n** %s\n", __func__);

	left->root->current = left;
	right->root->current = right;
	left->algo_data = atom_patience_left;
	right->algo_data = atom_patience_right;

	/* Find those lines that appear exactly once in 'left' and exactly once
	 * in 'right'. */
	rc = diff_atoms_mark_unique_in_both(left, right, &unique_in_both_count);
	if (rc)
		goto free_and_exit;

	debug("unique_in_both_count %u\n", unique_in_both_count);
	debug("left:\n");
	debug_dump(left);
	debug("right:\n");
	debug_dump(right);

	if (!unique_in_both_count) {
		/* Cannot apply Patience, tell the caller to use fallback_algo
		 * instead. */
		rc = DIFF_RC_USE_DIFF_ALGO_FALLBACK;
		goto free_and_exit;
	}

	rc = diff_atoms_swallow_identical_neighbors(left, right,
						    &unique_in_both_count);
	if (rc)
		goto free_and_exit;
	debug("After swallowing identical neighbors: unique_in_both = %u\n",
	      unique_in_both_count);

	rc = ENOMEM;

	/* An array of Longest Common Sequence is the result of the below
	 * subscope: */
	unsigned int lcs_count = 0;
	struct diff_atom *lcs_tail = NULL;

	{
		/* This subscope marks the lifetime of the atom_pointers
		 * allocation */

		/* One chunk of storage for atom pointers */
		struct diff_atom **atom_pointers;
		atom_pointers = recallocarray(NULL, 0, unique_in_both_count * 2,
					      sizeof(struct diff_atom*));
		if (atom_pointers == NULL)
			return ENOMEM;
		/* Half for the list of atoms that still need to be put on
		 * stacks */
		struct diff_atom **uniques = atom_pointers;

		/* Half for the patience sort state's "card stacks" -- we
		 * remember only each stack's topmost "card" */
		struct diff_atom **patience_stacks;
		patience_stacks = atom_pointers + unique_in_both_count;
		unsigned int patience_stacks_count = 0;

		/* Take all common, unique items from 'left' ... */

		struct diff_atom *atom;
		struct diff_atom **uniques_end = uniques;
		diff_data_foreach_atom(atom, left) {
			if (!PATIENCE(atom).unique_in_both)
				continue;
			*uniques_end = atom;
			uniques_end++;
		}

		/* ...and sort them to the order found in 'right'.
		 * The idea is to find the leftmost stack that has a higher line
		 * number and add it to the stack's top.
		 * If there is no such stack, open a new one on the right. The
		 * line number is derived from the atom*, which are array items
		 * and hence reflect the relative position in the source file.
		 * So we got the common-uniques from 'left' and sort them
		 * according to PATIENCE(atom).pos_in_other. */
		unsigned int i;
		for (i = 0; i < unique_in_both_count; i++) {
			atom = uniques[i];
			unsigned int target_stack;
			target_stack = find_target_stack(atom, patience_stacks,
							 patience_stacks_count);
			assert(target_stack <= patience_stacks_count);
			patience_stacks[target_stack] = atom;
			if (target_stack == patience_stacks_count)
				patience_stacks_count++;

			/* Record a back reference to the next stack on the
			 * left, which will form the final longest sequence
			 * later. */
			PATIENCE(atom).prev_stack = target_stack ?
				patience_stacks[target_stack - 1] : NULL;

			{
				int xx;
				for (xx = 0; xx < patience_stacks_count; xx++) {
					debug(" %s%d",
					      (xx == target_stack) ? ">" : "",
					      diff_atom_idx(right,
							    PATIENCE(patience_stacks[xx]).pos_in_other));
				}
				debug("\n");
			}
		}

		/* backtrace through prev_stack references to form the final
		 * longest common sequence */
		lcs_tail = patience_stacks[patience_stacks_count - 1];
		lcs_count = patience_stacks_count;

		/* uniques and patience_stacks are no longer needed.
		 * Backpointers are in PATIENCE(atom).prev_stack */
		free(atom_pointers);
	}

	lcs = recallocarray(NULL, 0, lcs_count, sizeof(struct diff_atom*));
	struct diff_atom **lcs_backtrace_pos = &lcs[lcs_count - 1];
	struct diff_atom *atom;
	for (atom = lcs_tail; atom; atom = PATIENCE(atom).prev_stack, lcs_backtrace_pos--) {
		assert(lcs_backtrace_pos >= lcs);
		*lcs_backtrace_pos = atom;
	}

	unsigned int i;
	if (DEBUG) {
		debug("\npatience LCS:\n");
		for (i = 0; i < lcs_count; i++) {
			debug("\n L "); debug_dump_atom(left, right, lcs[i]);
			debug(" R "); debug_dump_atom(right, left,
						      PATIENCE(lcs[i]).pos_in_other);
		}
	}


	/* TODO: For each common-unique line found (now listed in lcs), swallow
	 * lines upwards and downwards that are identical on each side. Requires
	 * a way to represent atoms being glued to adjacent atoms. */

	debug("\ntraverse LCS, possibly recursing:\n");

	/* Now we have pinned positions in both files at which it makes sense to
	 * divide the diff problem into smaller chunks. Go into the next round:
	 * look at each section in turn, trying to again find common-unique
	 * lines in those smaller sections. As soon as no more are found, the
	 * remaining smaller sections are solved by Myers. */
	/* left_pos and right_pos are indexes in left/right->atoms.head until
	 * which the atoms are already handled (added to result chunks). */
	unsigned int left_pos = 0;
	unsigned int right_pos = 0;
	for (i = 0; i <= lcs_count; i++) {
		struct diff_atom *atom;
		struct diff_atom *atom_r;
		/* left_idx and right_idx are indexes of the start of this
		 * section of identical lines on both sides.
		 * left_pos marks the index of the first still unhandled line,
		 * left_idx is the start of an identical section some way
		 * further down, and this loop adds an unsolved chunk of
		 * [left_pos..left_idx[ and a solved chunk of
		 * [left_idx..identical_lines.end[. */
		unsigned int left_idx;
		unsigned int right_idx;
		int already_done_count = 0;

		debug("iteration %u of %u  left_pos %u  right_pos %u\n",
		      i, lcs_count, left_pos, right_pos);

		if (i < lcs_count) {
			atom = lcs[i];
			atom_r = PATIENCE(atom).pos_in_other;
			debug("lcs[%u] = left[%u] = right[%u]\n", i,
			      diff_atom_idx(left, atom), diff_atom_idx(right, atom_r));
			left_idx = PATIENCE(atom).identical_lines.start;
			right_idx = PATIENCE(atom_r).identical_lines.start;
			debug(" identical lines l %u-%u  r %u-%u\n",
			      PATIENCE(atom).identical_lines.start, PATIENCE(atom).identical_lines.end,
			      PATIENCE(atom_r).identical_lines.start, PATIENCE(atom_r).identical_lines.end);
		} else {
			/* There are no more identical lines until the end of
			 * left and right. */
			atom = NULL;
			atom_r = NULL;
			left_idx = left->atoms.len;
			right_idx = right->atoms.len;
		}

		if (right_idx < right_pos) {
			/* This may happen if common-unique lines were in a
			 * different order on the right, and then ended up
			 * consuming the same identical atoms around a pair of
			 * common-unique atoms more than once.
			 * See also marker the other place marked with (1). */
			already_done_count = right_pos - right_idx;
			left_idx += already_done_count;
			right_idx += already_done_count;
			/* Paranoia: make sure we're skipping just an
			 * additionally joined identical line around it, and not
			 * the common-unique line itself. */
			assert(left_idx <= diff_atom_idx(left, atom));
		}

		/* 'atom' (if not NULL) now marks an atom that matches on both
		 * sides according to patience-diff (a common-unique identical
		 * atom in both files).
		 * Handle the section before and the atom itself; the section
		 * after will be handled by the next loop iteration -- note that
		 * i loops to last element + 1 ("i <= lcs_count"), so that there
		 * will be another final iteration to pick up the last remaining
		 * items after the last LCS atom.
		 */

		debug("iteration %u  left_pos %u  left_idx %u"
		      "  right_pos %u  right_idx %u\n",
		      i, left_pos, left_idx, right_pos, right_idx);

		/* Section before the matching atom */
		struct diff_atom *left_atom = &left->atoms.head[left_pos];
		unsigned int left_section_len = left_idx - left_pos;

		struct diff_atom *right_atom = &(right->atoms.head[right_pos]);
		unsigned int right_section_len = right_idx - right_pos;

		if (left_section_len && right_section_len) {
			/* Record an unsolved chunk, the caller will apply
			 * inner_algo() on this chunk. */
			if (!diff_state_add_chunk(state, false,
						  left_atom, left_section_len,
						  right_atom,
						  right_section_len))
				goto free_and_exit;
		} else if (left_section_len && !right_section_len) {
			/* Only left atoms and none on the right, they form a
			 * "minus" chunk, then. */
			if (!diff_state_add_chunk(state, true,
						  left_atom, left_section_len,
						  right_atom, 0))
				goto free_and_exit;
		} else if (!left_section_len && right_section_len) {
			/* No left atoms, only atoms on the right, they form a
			 * "plus" chunk, then. */
			if (!diff_state_add_chunk(state, true,
						  left_atom, 0,
						  right_atom, right_section_len))
				goto free_and_exit;
		}
		/* else: left_section_len == 0 and right_section_len == 0, i.e.
		 * nothing here. */

		/* The atom found to match on both sides forms a chunk of equals
		 * on each side. In the very last iteration of this loop, there
		 * is no matching atom, we were just cleaning out the remaining
		 * lines. */
		if (atom) {
			void *ok;
			unsigned int left_start = PATIENCE(atom).identical_lines.start;
			unsigned int left_len = diff_range_len(&PATIENCE(atom).identical_lines);
			unsigned int right_start = PATIENCE(atom_r).identical_lines.start;
			unsigned int right_len = diff_range_len(&PATIENCE(atom_r).identical_lines);

			left_start += already_done_count;
			left_len -= already_done_count;
			right_start += already_done_count;
			right_len -= already_done_count;

			ok = diff_state_add_chunk(state, true,
				left->atoms.head + left_start, left_len,
				right->atoms.head + right_start, right_len);
			if (!ok)
				goto free_and_exit;
			left_pos = PATIENCE(atom).identical_lines.end;
			right_pos = PATIENCE(atom_r).identical_lines.end;
		} else {
			left_pos = left_idx + 1;
			right_pos = right_idx + 1;
		}
		debug("end of iteration %u  left_pos %u  left_idx %u"
		      "  right_pos %u  right_idx %u\n",
		      i, left_pos, left_idx, right_pos, right_idx);
	}
	debug("** END %s\n", __func__);

	rc = DIFF_RC_OK;

free_and_exit:
	left->root->current = NULL;
	right->root->current = NULL;
	free(atom_patience_left);
	free(atom_patience_right);
	if (lcs)
		free(lcs);
	return rc;
}
