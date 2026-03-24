class Solution {
public:
    string longestCommonPrefix(vector<string> &strs) {
        string res;
        char c;
        int len = strs[0].size(), size = strs.size(), tmp;

        for (int i = 1; i < size; i++) {
            tmp = strs[i].size();
            len = len < tmp ? len : tmp;
        }
        
        for (int j = 0; j < len; j++) {
            c = strs[0][j];

            for (int i = 1; i < size; i++) {
                if (c != strs[i][j]) return res;
            }

            res += c;
        }

        return res;
    }
};
