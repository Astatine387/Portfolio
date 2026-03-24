# 11. Container With Most Water

**Link:** https://leetcode.com/problems/container-with-most-water/description/

**Difficulty:** Medium

**Topics:** Array, Two Pointers, Greedy


## Approach

1\. Locate a cursor `l` in the leftmost index and another cursor `r` in the rightmost index. Let `height[i]` be the height of the wall in the index `i`. The amount of water can be stored is `min(height[l], height[r]) * (r - l)`.

2\. Move the cursor with the lower value to the other side until it finds a higher value than the last. As a cursor moves, the width of the "floor" narrows, so you have to find a higher wall to store more water.


## Result

**Submission Link:** https://leetcode.com/problems/container-with-most-water/submissions/1773552752/

**Language:** C++

**Runtime:** 0 ms (Beats 100.00%)

**Memory Usage:** 62.76 MB (Beats 97.01%)

**Time Complexity:** O(n)

**Space Complexity:** O(1)
