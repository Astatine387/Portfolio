# 5. Longest Palindromic Substring

**Link:** https://leetcode.com/problems/longest-palindromic-substring/description/

**Difficulty:** Medium

**Topics:** Two Pointers, String, Dynamic Programming


## Approach

1\. For each index `i` on the input string `s`, expand two pointers `l` and `r` each to left and to right, while `s[l] == s[r]` to search odd-lengthed palindroms.

2\. For each index `i` on the input string `s`, expand two pointers `l` and `r` each to left and to right, while `s[l] == s[r + 1]` to search even-lengthed palindroms.

3\. Store the longest palindrom's length and its starting index. Return the longest palindromic substring using its starting index and length.


## Result

**Submission Link:** https://leetcode.com/problems/longest-palindromic-substring/submissions/1771262689/

**Language:** C++

**Runtime:** 6 ms (Beats 90.50%)

**Memory Usage:** 9.25 MB (Beats 92.61%)

**Time Complexity:** O(n^2)

**Space Complexity:** O(1)
