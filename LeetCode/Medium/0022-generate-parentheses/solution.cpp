class Solution {
private:
    vector<string> res;
    string tmp;
    int l = 0, r = 0, crs = 0, max;
    
    void func() {
        if (r == max) {
            res.push_back(tmp);
            return;
        }
        
        if (l < max) {
            tmp[crs++] = '(';
            l++;
            
            func();
            
            crs--, l--;
        }
        
        if (l > r) {
            tmp[crs++] = ')';
            r++;
            
            func();
            
            crs--, r--;
        }
    }
    
public:
    vector<string> generateParenthesis(int n) {
        max = n;

        tmp.resize(n * 2);
        func();
        
        return res;
    }
};
