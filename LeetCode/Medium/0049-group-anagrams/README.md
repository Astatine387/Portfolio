# 49. Group Anagrams

**Link:** https://leetcode.com/problems/group-anagrams/description/

**Difficulty:** Medium

**Topics:** Array, Hash Table, String, Sorting


## Approach

1\. For each string, make its sorted version and use it as key. If multiple strings have the same key, they are anagrams.

2\. Store the strings into a hash table using their sorted version as a key. It automatically groups strings by anagram.


## Result

**Submission Link:** https://leetcode.com/problems/group-anagrams/submissions/1773528495/

**Language:** C++

**Runtime:** 11 ms (Beats 91.30%)

**Memory Usage:** 25.00 MB (Beats 66.07%)

**Time Complexity:** O(n * m * log m)

**Space Complexity:** O(n * m)
