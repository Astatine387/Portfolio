class Solution {
public:
    int maxProfit(vector<int> &prices) {
        int min = prices[0], res = 0, size = prices.size();
        
        for (int i = 1; i < size; i++) {
            res = res > prices[i] - min ? res : prices[i] - min;
            min = min < prices[i]       ? min : prices[i]      ;
        }
        
        return res;
    }
};
