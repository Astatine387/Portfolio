# 4. Median of Two Sorted Arrays

**Description:** https://leetcode.com/problems/median-of-two-sorted-arrays/description/

**Difficulty:** Hard

**Topics:** Array, Binary Search, Divide and Conquer


## Approach

1\. In a sorted array, the median value must have the same number of elements on its left and right, and the elements on the left of the median must be not larger than those on the right of it.

2\. Let `n` be the number of elements in the left of `crs0` on `vec0`. Let `m` be the number of elements in the left of `crs1` on `vec1`.

3\. Conduct binary search on `vec0`. Set `crs1` so that `m + n = half`. If the maximum in the left of each index are not larger than the minimum in the right of both indices, the conditions specified in 1 are met and the median is found. Otherwise, continue the binary search.


## Result

**Submission:** https://leetcode.com/problems/median-of-two-sorted-arrays/submissions/1759179837/

**Language:** C++

**Runtime:** 0 ms (Beats 100%)

**Memory Usage:** 94.89 MB (Beats 99.58%)

**Time Complexity:** O(log(min(n, m)))

**Space Complexity:** O(1)


## Attribution

LeetCode Editorial: https://leetcode.com/problems/median-of-two-sorted-arrays/editorial/
