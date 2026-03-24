# 2. Add Two Numbers

**Link:** https://leetcode.com/problems/add-two-numbers/description/

**Difficulty:** Medium

**Topics:** Linked List, Math, Recursion


## Approach

1\. Iterate two lists simultaneously. Calculate the current digit and carry.

2\. If one list ends, iterate the other, and do the same.

3\. Check the carry remains after the both list ends. If so, add the digit `1`. 


## Result

**Submission Link:** https://leetcode.com/problems/add-two-numbers/submissions/1772395249/

**Language:** C++

**Runtime:** 0 ms (Beats 100%)

**Memory Usage:** 76.97 MB (Beats 92.11%)

**Time Complexity:** O(max(n,m))

**Space Complexity:** O(max(n,m))
