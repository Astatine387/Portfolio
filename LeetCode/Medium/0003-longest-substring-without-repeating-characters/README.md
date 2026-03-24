# 4. Longest Substring Without Repeating Characters

**Link:** https://leetcode.com/problems/longest-substring-without-repeating-characters/description/

**Difficulty:** Medium

**Topics:** Hash Table, String, Sliding Window


## Approach

1\. Expand the right end of sliding window and store characters it includes to hash table.

2\. If there is a repeated character, contract the left end of sliding window and remove characters it excludes from hash table, until there is no repeated character.


## Result

**Submission Link:** https://leetcode.com/problems/longest-substring-without-repeating-characters/submissions/1766753937/

**Language:** C++

**Runtime:** 0 ms (Beats 100%)

**Memory Usage:** 10.38 MB (Beats 97.48%)

**Time Complexity:** O(n)

**Space Complexity:** O(1)
