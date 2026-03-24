# 56. Merge Intervals

**Link:** https://leetcode.com/problems/merge-intervals/description/

**Difficulty:** Medium

**Topics:** Array, Sorting


## Approach

1\. Sort the array by increasing order.

2\. Let the first interval be `cur`. If new interval overlaps with `cur`, merge it into `cur`. Else, add `cur` to result and set the new interval to be `cur`.


## Result

**Submission Link:** https://leetcode.com/problems/merge-intervals/submissions/1766733581/

**Language:** C++

**Runtime:** 3 ms (Beats 89.44%)

**Memory Usage:** 23.59 MB (Beats 96.80%)

**Time Complexity:** O(n * log n)

**Space Complexity:** O(n)
