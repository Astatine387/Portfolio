class Solution {
public:
    double findMedianSortedArrays(vector<int> &vec0, vector<int> &vec1) {
        int size0 = vec0.size(), size1 = vec1.size();

        if (size0 > size1) return findMedianSortedArrays(vec1, vec0);

        int half = (size0 + size1 + 1) >> 1, l = 0, r = size0;
        int crs0, crs1, lmax0, lmax1, rmin0, rmin1;

        while (l <= r) {
            crs0 = (l + r) >> 1;
            crs1 = half - crs0;

            lmax0 = crs0 > 0     ? vec0[crs0 - 1] : -1000001;
            rmin0 = crs0 < size0 ? vec0[crs0]     :  1000001;

            lmax1 = crs1 > 0     ? vec1[crs1 - 1] : -1000001;
            rmin1 = crs1 < size1 ? vec1[crs1]     :  1000001;

            if (lmax0 <= rmin1 && lmax1 <= rmin0) break;
            else if (lmax0 > rmin1) r = crs0 - 1;
            else l = crs0 + 1;
        }

        return (size0 + size1) & 1 ? max(lmax0, lmax1) : (max(lmax0, lmax1) + min(rmin0, rmin1)) / 2.0;
    }
};
