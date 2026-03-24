class Solution {
public:
    string longestPalindrome(string str) {
        int size = str.size();
        int idx = 0, len = 1, range;

        for (int i = 0; i < size; i++) {
            range = i < size - i ? i : size - i;

            for (int j = 1; j <= range && str[i - j] == str[i + j]; j++) {
                len = len > j * 2 + 1 ? len : j * 2 + 1;
                idx = len > j * 2 + 1 ? idx : i - j;
            }
        }

        for (int i = 0; i < size; i++) {
            range = i < size - i - 1 ? i : size - i - 1;

            for (int j = 0; j <= range && str[i - j] == str[i + j + 1]; j++) {
                len = len > j * 2 + 2 ? len : j * 2 + 2;
                idx = len > j * 2 + 2 ? idx : i - j;
            }
        }
        
        return str.substr(idx, len);
    }
};
