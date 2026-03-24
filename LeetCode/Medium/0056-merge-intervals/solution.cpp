class Solution {
public:
    vector<vector<int>> merge(vector<vector<int>> &vec) {
        vector<vector<int>> res;
        int size = vec.size(), l, r;

        sort(vec.begin(), vec.end(), [](vector<int> &a, vector<int> &b) {
            return a[0] < b[0];
        });

        l = vec[0][0], r = vec[0][1];

        for (int i = 0; i < size; i++) {
            if (r < vec[i][0]) {
                res.push_back({ l, r });
                l = vec[i][0];
            }

            r = r > vec[i][1] ? r : vec[i][1];
        }

        res.push_back({ l, r });

        return res;
    }
};