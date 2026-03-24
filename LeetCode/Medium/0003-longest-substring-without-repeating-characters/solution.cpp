class Solution {
public:
    int lengthOfLongestSubstring(string str) {
        vector<bool> hash(256);
        int size = str.size(), l = 0, r = 0, res = 0;
        
        while (r < size) {
            if (!hash[str[r]]) {
                hash[str[r++]] = 1;
            }
            else {
                res = res > r - l ? res : r - l;
                hash[str[l++]] = 0;
            }
        }
        
        res = res > r - l ? res : r - l;
        
        return res;
    }
};