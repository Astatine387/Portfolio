# 1249\. Minimum Remove to Make Valid Parentheses

**Link:** https://leetcode.com/problems/minimum-remove-to-make-valid-parentheses/description/

**Difficulty:** Medium

**Topics:** String, Stack



## Approach

1\. Iterate the string from left to right. If there is a right bracket where there is no corresponding left bracket, remove it.

2\. Iterate the string from right to left. If there is a left bracket where there is no corresponding right bracket, remove it.



## Result

**Submission Link:** https://leetcode.com/problems/minimum-remove-to-make-valid-parentheses/submissions/1764575045/

**Language:** C++

**Runtime:** 5 ms (Beats 80.63%)

**Memory Usage:** 13.34 MB (Beats 87.62%)

**Time Complexity:** O(n)

**Space Complexity:** O(n)

