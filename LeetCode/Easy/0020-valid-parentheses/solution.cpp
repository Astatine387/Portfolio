class Solution {
public:
    bool isValid(string s) {
        stack<char> stk;
        int size = s.size();

        if (size & 1) return 0;

        for (int i = 0; i < size; i++) {
            if (s[i] == '(' || s[i] == '[' || s[i] == '{') {
                stk.push(s[i]);
            }
            else if (s[i] == ')') {
                if (stk.empty() || stk.top() != '(') return 0;
                else stk.pop();
            }
            else if (s[i] == ']') {
                if (stk.empty() || stk.top() != '[') return 0;
                else stk.pop();
            }
            else if (s[i] == '}') {
                if (stk.empty() || stk.top() != '{') return 0;
                else stk.pop();
            }
        }

        return stk.empty();
    }
};
