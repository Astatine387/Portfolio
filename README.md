## 1. Introduction

I'm Astatine387, a C/C++ software engineer. I mainly build cross-platform desktop applications involving security. I value simple, practical design with minimal but necessary features. I'm currently open to software engineering opportunities in the United States.

## 2. Tech Stack

| Category                   | Tools                                                  |
| -------------------------- | ------------------------------------------------------ |
| **Languages**              | C, C++20                                               |
| **Libraries & Frameworks** | C++ STL, Argon2, OpenSSL, Qt6                          |
| **Build & Package**        | CMake, vcpkg                                           |
| **Testing & Quality**      | Google Test, Google Benchmark, cppcheck, Codecov, lcov |
| **CI/CD**                  | GitHub Actions                                         |
| **Platforms**              | Windows, Linux                                         |

## 3. Projects
### 3-1. [FileEncryption](./Projects/FileEncryption)

![Build](https://github.com/Astatine387/Portfolio/actions/workflows/build-fileencryption.yml/badge.svg) ![Codecov](https://codecov.io/gh/Astatine387/Portfolio/branch/main/graph/badge.svg?flag=fileencryption)

GUI, password-based file encryption/decryption tool.

**Features:**
* 2 GB/s throughput
* AES-256-GCM for encryption and integrity check
* Argon2id memory hard and data independent key derivation
* Real-time progress tracking and cancellation support
* Cross-platform support for Windows and Linux

### 3-2. [PasswordManager](./Projects/PasswordManager)

![Build](https://github.com/Astatine387/Portfolio/actions/workflows/build-passwordmanager.yml/badge.svg) ![Codecov](https://codecov.io/gh/Astatine387/Portfolio/branch/main/graph/badge.svg?flag=passwordmanager)

GUI-based, encrypted password file manager tool.

**Features:**
* AES-256-GCM for encryption and integrity check
* Argon2id memory hard and data independent key derivation
* Random password generator with customizable length and special characters
* Automatic clipboard clear after password copy
* Search and filter entries by keyword
* Cross-platform support for Windows and Linux

## 4. LeetCode

**Profile:** https://leetcode.com/u/Astatine387/

**Statistics:** </br>
![LeetCode](https://leetcard.jacoblin.cool/Astatine387?theme=dark&font=Noto%20Sans)

**Badges:** </br>
![LeetCode Badges](https://leetcode-badge-showcase.vercel.app/api?username=Astatine387)

**Curated Problems:** 

| Title                                                                                                                      | Difficulty                                            | Topics                                   | Time             | Space       | Runtime        | Memory             | Submission                                                                                                                                                                                                                                                                   |
| -------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------- | ---------------------------------------- | ---------------- | ----------- | -------------- | ------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [4. Median of Two Sorted Arrays](./LeetCode/Hard/0004-median-of-two-sorted-arrays)                                         | ![Hard](https://img.shields.io/badge/Hard-d32f2f)     | Array, Binary Search, Divide and Conquer | O(log(min(n,m))) | O(1)        | 0 ms (100%)    | 94.89 MB (99.58%)  | [![Solution](https://img.shields.io/badge/Solution-%23FFA116?logo=leetcode&logoColor=white)](https://leetcode.com/problems/median-of-two-sorted-arrays/submissions/1759179837/)                                                                                              |
| [42. Trapping Rain Water](./LeetCode/Hard/0042-trapping-rain-water)                                                        | ![Hard](https://img.shields.io/badge/Hard-d32f2f)     | Array, Two Pointers, DP, Stack           | O(n)             | O(n)        | 0 ms (100%)    | 26.81 MB (44.85%)  | [![Solution](https://img.shields.io/badge/Solution-%23FFA116?logo=leetcode&logoColor=white)](https://leetcode.com/problems/trapping-rain-water/submissions/1759018110/)                                                                                                      |
| [2. Add Two Numbers](./LeetCode/Medium/0002-add-two-numbers)                                                               | ![Medium](https://img.shields.io/badge/Medium-ed8936) | Linked List, Math, Recursion             | O(max(n,m))      | O(max(n,m)) | 0 ms (100%)    | 76.97 MB (92.11%)  | [![Solution](https://img.shields.io/badge/Solution-%23FFA116?logo=leetcode&logoColor=white)](https://leetcode.com/problems/add-two-numbers/submissions/1772395249/)                                                                                                          |
| [3. Longest Substring Without Repeating Characters](./LeetCode/Medium/0003-longest-substring-without-repeating-characters) | ![Medium](https://img.shields.io/badge/Medium-ed8936) | Hash Table, String, Sliding Window       | O(n)             | O(1)        | 0 ms (100%)    | 10.38 MB (97.48%)  | [![Solution](https://img.shields.io/badge/Solution-%23FFA116?logo=leetcode&logoColor=white)](https://leetcode.com/problems/longest-substring-without-repeating-characters/submissions/1766753937/)                                                                           |
| [5. Longest Palindromic Substring](./LeetCode/Medium/0005-longest-palindromic-substring)                                   | ![Medium](https://img.shields.io/badge/Medium-ed8936) | Two Pointers, String, DP                 | O(n²)            | O(1)        | 6 ms (90.50%)  | 9.25 MB (92.61%)   | [![Solution](https://img.shields.io/badge/Solution-%23FFA116?logo=leetcode&logoColor=white)](https://leetcode.com/problems/longest-palindromic-substring/submissions/1771262689/)                                                                                            |
| [11. Container With Most Water](./LeetCode/Medium/0011-container-with-most-water)                                          | ![Medium](https://img.shields.io/badge/Medium-ed8936) | Array, Two Pointers, Greedy              | O(n)             | O(1)        | 0 ms (100%)    | 62.76 MB (97.01%)  | [![Solution](https://img.shields.io/badge/Solution-%23FFA116?logo=leetcode&logoColor=white)](https://leetcode.com/problems/container-with-most-water/submissions/1773552752/)                                                                                                |
| [22. Generate Parentheses](./LeetCode/Medium/0022-generate-parentheses)                                                    | ![Medium](https://img.shields.io/badge/Medium-ed8936) | String, DP, Backtracking                 | O(4ⁿ/√n)         | O(n)        | 1 ms (86.82%)  | 13.26 MB (77.54%)  | [![Solution](https://img.shields.io/badge/Solution-%23FFA116?logo=leetcode&logoColor=white)](https://leetcode.com/problems/generate-parentheses/submissions/1772442236/)                                                                                                     |
| [49. Group Anagrams](./LeetCode/Medium/0049-group-anagrams)                                                                | ![Medium](https://img.shields.io/badge/Medium-ed8936) | Array, Hash Table, String, Sorting       | O(n·m·log m)     | O(n·m)      | 11 ms (91.30%) | 25.00 MB (66.07%)  | [![Solution](https://img.shields.io/badge/Solution-%23FFA116?logo=leetcode&logoColor=white)](https://leetcode.com/problems/group-anagrams/submissions/1773528495/)                                                                                                           |
| [56. Merge Intervals](./LeetCode/Medium/0056-merge-intervals)                                                              | ![Medium](https://img.shields.io/badge/Medium-ed8936) | Array, Sorting                           | O(n·log n)       | O(n)        | 3 ms (89.44%)  | 23.59 MB (96.80%)  | [![Solution](https://img.shields.io/badge/Solution-%23FFA116?logo=leetcode&logoColor=white)](https://leetcode.com/problems/merge-intervals/submissions/1766733581/)                                                                                                          |
| [146. LRU Cache](./LeetCode/Medium/0146-lru-cache)                                                                         | ![Medium](https://img.shields.io/badge/Medium-ed8936) | Hash Table, Linked List, Design          | O(1)             | O(n)        | 61 ms (85.29%) | 173.09 MB (82.59%) | [![Solution](https://img.shields.io/badge/Solution-%23FFA116?logo=leetcode&logoColor=white)](https://leetcode.com/problems/lru-cache/submissions/1763431481/)                                                                                                                |
| [200. Number of Islands](./LeetCode/Medium/0200-number-of-islands)                                                         | ![Medium](https://img.shields.io/badge/Medium-ed8936) | Array, DFS, BFS, Union Find              | O(m·n)           | O(m·n)      | 22 ms (88.52%) | 15.81 MB (100%)    | [![Solution](https://img.shields.io/badge/Solution-%23FFA116?logo=leetcode&logoColor=white)](https://leetcode.com/problems/number-of-islands/submissions/1315980601/)                                                                                                        |
| [1. Two Sum](./LeetCode/Easy/0001-two-sum)                                                                                 | ![Easy](https://img.shields.io/badge/Easy-43a047)     | Array, Hash Table                        | O(n)             | O(n)        | 0 ms (100%)    | 14.78 MB (50.63%)  | [![Solution](https://img.shields.io/badge/Solution-%23FFA116?logo=leetcode&logoColor=white)](https://leetcode.com/problems/two-sum/submissions/1774620704/)                                                                                                                  |
| [14. Longest Common Prefix](./LeetCode/Easy/0014-longest-common-prefix)                                                    | ![Easy](https://img.shields.io/badge/Easy-43a047)     | Array, String, Trie                      | O(m·n)           | O(1)        | 0 ms (100%)    | 11.66 MB (95.10%)  | [![Solution](https://img.shields.io/badge/Solution-%23FFA116?logo=leetcode&logoColor=white)](https://leetcode.com/problems/longest-common-prefix/submissions/1775660497/)                                                                                                    |
| [20. Valid Parentheses](./LeetCode/Easy/0020-valid-parentheses)                                                            | ![Easy](https://img.shields.io/badge/Easy-43a047)     | String, Stack                            | O(n)             | O(n)        | 0 ms (100%)    | 8.64 MB (88.89%)   | [![Solution](https://img.shields.io/badge/Solution-%23FFA116?logo=leetcode&logoColor=white)](https://leetcode.com/problems/valid-parentheses/submissions/1667906098/)                                                                                                        |
| [118. Pascal's Triangle](./LeetCode/Easy/0118-pascals-triangle)                                                            | ![Easy](https://img.shields.io/badge/Easy-43a047)     | Array, DP                                | O(n²)            | O(n²)       | 0 ms (100%)    | 6.42 MB (100%)     | [![Solution](https://img.shields.io/badge/Solution-%23FFA116?logo=leetcode&logoColor=white)](https://leetcode.com/problems/pascals-triangle/submissions/749985216/)                                                                                                          |
| [121. Best Time to Buy and Sell Stock](./LeetCode/Easy/0121-best-time-to-buy-and-sell-stock)                               | ![Easy](https://img.shields.io/badge/Easy-43a047)     | Array, DP                                | O(n)             | O(1)        | 0 ms (100%)    | 97.28 MB (86.43%)  | [![Solution](https://img.shields.io/badge/Solution-%23FFA116?logo=leetcode&logoColor=white)]([https://leetcode.com/problems/best-time-to-buy-and-sell-stock/submissions/1774620704/](https://leetcode.com/problems/best-time-to-buy-and-sell-stock/submissions/1774654779/)) |

## 5. Contact

**Email:** astatine387@outlook.com
**LinkedIn:** https://www.linkedin.com/in/astatine387/
