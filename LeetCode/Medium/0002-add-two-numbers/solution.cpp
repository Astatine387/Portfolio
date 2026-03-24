class Solution {
public:
    ListNode *addTwoNumbers(ListNode *list0, ListNode *list1) {
        ListNode *res = new ListNode(), *crs0 = list0, *crs1 = list1, *crs2 = res;
        int carry = 0, sum;

        while (crs0 && crs1) {
            sum = crs0->val + crs1->val + carry;
            
            carry = sum > 9 ? 1 : 0;
            sum = sum > 9 ? sum - 10 : sum;
            
            crs2->next = new ListNode(sum);
            
            crs0 = crs0->next;
            crs1 = crs1->next;
            crs2 = crs2->next;
        }
        
        while (crs0) {
            sum = crs0->val + carry;
            
            carry = sum > 9 ? 1 : 0;
            sum = sum > 9 ? sum - 10 : sum;
            
            crs2->next = new ListNode(sum);
            
            crs0 = crs0->next;
            crs2 = crs2->next;
        }
        
        while (crs1) {
            sum = crs1->val + carry;
            
            carry = sum > 9 ? 1 : 0;
            sum = sum > 9 ? sum - 10 : sum;

            crs2->next = new ListNode(sum);
            
            crs1 = crs1->next;
            crs2 = crs2->next;
        }
        
        if (carry) crs2->next = new ListNode(1);
        
        return res->next;
    }
};
