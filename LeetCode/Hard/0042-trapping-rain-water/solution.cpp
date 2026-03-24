class Solution {
public:
    int trap(vector<int> &vec) {
        int max_l = vec[0], size = vec.size(), res = 0, tmp;
        vector<int> max_r(size);

        max_r[size - 1] = vec[size - 1];

        for (int i = size - 2; i >= 0 ; i--) max_r[i] = max_r[i + 1] > vec[i] ? max_r[i + 1] : vec[i];
        
        for (int i = 0; i < size; i++) {
            tmp = max_l < max_r[i] ? max_l : max_r[i];
            max_l = max_l > vec[i] ? max_l : vec[i];
            
            if (vec[i] < tmp) res += tmp - vec[i];
        }
        
        return res;
    }
};
