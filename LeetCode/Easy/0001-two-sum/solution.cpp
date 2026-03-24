class Solution {
public:
    vector<int> twoSum(vector<int> &nums, int tar) {
        unordered_map<int, int> umap;
        int size = nums.size();

        for (int i = 0; i < size; i++) {
            if (umap.find(tar - nums[i]) != umap.end()) return { umap[tar - nums[i]], i };
            else umap.insert({ nums[i], i });
        }

        return {};
    }
};
