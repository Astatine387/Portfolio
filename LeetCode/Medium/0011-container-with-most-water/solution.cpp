class Solution {
public:
    int maxArea(vector<int> &vec) {
        int l = 0, r = vec.size() - 1, res = 0, tmp;
        
        while (l < r) {
            res = max(res, min(vec[l], vec[r]) * (r - l));

            if (vec[l] < vec[r]) {
                tmp = vec[l];

                while (l < r && vec[l] <= tmp) l++;
            }
            else {
                tmp = vec[r];

                while (l < r && vec[r] <= tmp) r--;
            }
        }
        
        return res;
    }
};
