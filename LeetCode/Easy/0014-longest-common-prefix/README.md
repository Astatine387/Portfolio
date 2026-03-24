# 14. Longest Common Prefix

**Description:** https://leetcode.com/problems/longest-common-prefix/description/

**Difficulty:** Easy

**Topics:** Array, String, Trie


## Approach

1\. Iterate over all strings and compare their `n`th characters. If they are all the same, add it to the longest common prefix. Repeat this until there is a different `n`th character or `n` reaches the length of the shortest string.


## Result

**Submission:** https://leetcode.com/problems/longest-common-prefix/submissions/1775660497/

**Language:** C++

**Runtime:** 0 ms (Beats 100%)

**Memory Usage:** 11.66 MB (Beats 95.10%)

**Time Complexity:** O(n * m)

**Space Complexity:** O(1)
