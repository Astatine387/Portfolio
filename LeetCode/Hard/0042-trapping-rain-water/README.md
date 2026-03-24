# 42. Trapping Rain Water

**Description:** https://leetcode.com/problems/trapping-rain-water/description/

**Difficulty:** Hard

**Topics:** Array, Two Pointers, Dynamic Programming, Stack, Monotonic Stack


## Approach

1\. For each index, calculate height of the highest wall in its right. Let `max_r[i]` be the height of the highest wall in the right of index `i`.

2\. Iterate each index, calculate height of the highest wall in its left. Let `max_l` be the height of the highest wall in the left of the current index.

3\. Choose the smaller value among `max_l` and `max_r[i]`. Let it be `tmp`.

4\. If `tmp` is larger than `vec[i]`, the height of the "floor" in the current index, then rain water can be trapped there. Add `tmp - vec[i]`, the amount of rain water can be trapped upon index `i`, to `res`.


## Result

**Submission:** https://leetcode.com/problems/trapping-rain-water/submissions/1759018110/

**Language:** C++

**Runtime:** 0 ms (Beats 100%)

**Memory Usage:** 26.81 MB (Beats 44.85%)

**Time Complexity:** O(n)

**Space Complexity:** O(n)

