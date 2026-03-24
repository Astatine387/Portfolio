class LRUCache {
private:
    list<pair<int, int>> cache;
    unordered_map<int, list<pair<int, int>>::iterator> umap;
    int cur_size = 0, max_size;

public:
    LRUCache(int cap) {
        max_size = cap;
    }
    
    int get(int key) {
        if (umap.find(key) == umap.end()) {
            return -1;
        }
        else {
            cache.splice(cache.begin(), cache, umap[key]);
            return umap[key]->second;
        }
    }
    
    void put(int key, int val) {
        if (umap.find(key) == umap.end()) {
            if (cur_size == max_size) {
                umap.erase(cache.back().first);
                cache.pop_back();
            }
            else {
                cur_size++;
            }

            cache.push_front({ key, val });
            umap[key] = cache.begin();
        }
        else {
            cache.splice(cache.begin(), cache, umap[key]);
            umap[key]->second = val;
        }
    }
};
