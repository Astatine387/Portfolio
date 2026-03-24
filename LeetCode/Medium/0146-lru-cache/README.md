# 146. LRU Cache

**Link:** https://leetcode.com/problems/lru-cache/description/

**Difficulty:** Medium

**Topics:** Hash Table, Linked List, Design, Doubly-Linked List


## Approach

1\. Create a doubly-linked list which stores key-value pairs, and a hash table which stores pointers to each element of the list.

2\. New items are put in the front of the list. If it exceeds the maximum size, remove the item at the very back of the list.

3\. Whenever an item is referred or updated, move it to the front of the list.


## Result

**Submission Link:** https://leetcode.com/problems/lru-cache/submissions/1763431481/

**Language:** C++

**Runtime:** 61 ms (Beats 85.29%)

**Memory Usage:** 173.09 MB (Beats 82.59%)

**Time Complexity:** O(1)

**Space Complexity:** O(n)
