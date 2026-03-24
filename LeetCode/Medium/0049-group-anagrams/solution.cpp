class Solution {
public:    
    vector<vector<string>> groupAnagrams(vector<string> &vec) {
        unordered_map<string, vector<string>> umap;
        vector<vector<string>> res;
        string tmp;
        int size = vec.size();

        for (int i = 0; i < size; i++) {
            tmp = vec[i];
            sort(tmp.begin(), tmp.end());
            umap[tmp].push_back(vec[i]);
        }

        for (auto i = umap.begin(); i != umap.end(); i++) res.push_back(i->second);
        
        return res;
    }
};
