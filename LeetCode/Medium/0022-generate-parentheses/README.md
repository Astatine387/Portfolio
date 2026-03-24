# 22. Generate Parentheses

**Link:** https://leetcode.com/problems/generate-parentheses/description/

**Difficulty:** Medium

**Topics:** String, Dynamic Programming, Backtracking


## Approach

1\. If the number of left brackets is smaller than the maximum, add a left bracket.

2\. If the number of right brackets is smaller than the number of left brackets, add a right bracket.

3\. Repeat 1 and 2 until a string reaches the maximum length. If a string has reached the maximum length, add it to the result.


## Result

**Submission Link:** https://leetcode.com/problems/generate-parentheses/submissions/1772442236/

**Language:** C++

**Runtime:** 1 ms (Beats 86.82%)

**Memory Usage:** 13.26 MB (Beats 77.54%)

**Time Complexity:** O(4^n / Sqrt(n))

**Space Complexity:** O(n)
