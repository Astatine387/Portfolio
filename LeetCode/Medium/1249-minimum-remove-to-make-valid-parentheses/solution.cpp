class Solution {
public:
    string minRemoveToMakeValid(string s) {
        int size = s.size(), cnt = 0;
        string res = "";

        for (int i = 0; i < size; i++) {
            if (s[i] == '(') {
                cnt++;
            }
            else if (s[i] == ')') {
                if (cnt > 0) cnt--;
                else s[i] = ' ';
            }
        }

        cnt = 0;

        for (int i = size - 1; i >= 0; i--) {
            if (s[i] == ')') {
                cnt++;
            }
            else if (s[i] == '(') {
                if (cnt > 0) cnt--;
                else s[i] = ' ';
            }
        }

        for (int i = 0; i < size; i++) {
            if (s[i] != ' ') res += s[i];
        }

        return res;
    }
};
