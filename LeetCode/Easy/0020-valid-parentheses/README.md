# 121. Best Time to Buy and Sell Stock

**Description:** https://leetcode.com/problems/valid-parentheses/editorial/

**Difficulty:** Easy

**Topics:** String, Stack


## Approach

1\. If the current character is a left bracket, push it into the stack. If it is a right bracket, check whether it matches with the last one in the stack. If so, pop the last bracket from stack. If not, the input string is not valid.


## Result

**Submission:** https://leetcode.com/problems/valid-parentheses/submissions/1667906098/

**Language:** C++

**Runtime:** 0 ms (Beats 100%)

**Memory Usage:** 8.64 MB (Beats 88.89%)

**Time Complexity:** O(n)

**Space Complexity:** O(n)
