class Solution {
private:
    int res = 0, row, col;

    void dfs(vector<vector<char>> &grid, int x, int y) {
        if (x > 0 && grid[x - 1][y] == '1') {
            grid[x - 1][y] = '2';
            dfs(grid, x - 1, y);
        }

        if (y > 0 && grid[x][y - 1] == '1') {
            grid[x][y - 1] = '2';
            dfs(grid, x, y - 1);
        }

        if (x < row - 1 && grid[x + 1][y] == '1') {
            grid[x + 1][y] = '2';
            dfs(grid, x + 1, y);
        }

        if (y < col - 1 && grid[x][y + 1] == '1') {
            grid[x][y + 1] = '2';
            dfs(grid, x, y + 1);
        }
    }

public:
    int numIslands(vector<vector<char>> &grid) {
        row = grid.size(), col = grid[0].size();

        for (int i = 0; i < row; i++) {
            for (int j = 0; j < col; j++) {
                if (grid[i][j] == '1') {
                    grid[i][j] = '2';
                    dfs(grid, i, j);
                    res++;
                }
            }
        }

        return res;
    }
};
