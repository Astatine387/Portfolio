/**
 * @file    test_main.cpp
 * @brief   Entry point that runs every test in a working directory of its own
 * @author  Astatine387
 */

#include <gtest/gtest.h>

#include <cstdlib>
#include <filesystem>
#include <format>
#include <iostream>
#include <random>
#include <string>
#include <string_view>
#include <system_error>

namespace {

/* Under the directory the process was started in, which is the build directory for both ctest and CLion and so is
 * already ignored. Deliberately not /tmp: on Fedora and its derivatives that is a tmpfs, and these cases ask the file
 * system the kind of question -- what a directory fsync reports, what a rename refuses, whether permission bits bind
 * -- whose answer is the file system's to give, so they keep being asked of the one they have been asked of so far. */

constexpr std::string_view kScratchRoot = "test-scratch";

/* A name is drawn rather than counted, so that processes running in parallel need no agreement with each other. The
 * eight hex digits of a random_device result keep the path far inside the 260 characters Windows allows, and the
 * retries below cover the birthday case. */

constexpr int kNameAttempts = 64;

/**
 * @brief   Render a path for a message without narrowing it
 * @param   path    Path to render
 * @return  The path as UTF-8 text, or a placeholder when it cannot be spelled in it
 *
 * path::string() converts a wide path through the ANSI code page on Windows and loses, or outright fails on, whatever
 * that page cannot spell -- a build directory named in Hangul among it. platform_win32.cpp's ResolvePath reaches for
 * u8string for the same reason.
 *
 * That conversion is also the one step in this file that reports by throwing, and both callers are already delivering
 * bad news: one on its way to abort, the other warning about a directory it could not remove. Letting an exception out
 * of either would replace a message that names the problem with one that does not, so the path is the part given up
 * on. The error_code printed beside it is the half that says what went wrong.
 */
std::string Show(const std::filesystem::path& path) noexcept {
  try {
    const std::u8string text = path.u8string();

    return { reinterpret_cast<const char*>(text.data()), text.size() };
  }
  catch (...) {
    return "<unprintable>";  // Short enough to need no allocation of its own
  }
}

/**
 * @brief   Report why the working directory could not be arranged and end the process
 * @param   what    Step that failed
 * @param   path    Path it failed on
 * @param   ec      Reason the file system gave
 *
 * Carrying on would run the suite unisolated in the build directory, which is the bug this file exists to remove. That
 * state reads as a pass until some later run happens to order two cases the other way round, so it is worth a crash
 * here instead.
 */
[[noreturn]] void Fail(const char* what, const std::filesystem::path& path, const std::error_code& ec) {
  std::cerr << "test_main: " << what << " '" << Show(path) << "': " << ec.message() << '\n';

  std::abort();
}

/**
 * @brief   Give the owner full access to every directory in a tree
 * @param   dir     Directory to walk
 *
 * Cases that check what a vault does when a directory refuses it leave that directory at 0300 or 0600, and one
 * stripped of its search bit can no longer be listed, let alone emptied. The bits go back on the way down, ahead of
 * the point they are needed.
 *
 * Links are never followed. One case leaves a pair of them pointing at each other and another a chain that climbs out
 * of the directory it starts in, so only what the test itself created is touched.
 */
void RestoreOwnerAccess(const std::filesystem::path& dir) {
  namespace fs = std::filesystem;

  std::error_code ec;

  fs::permissions(dir, fs::perms::owner_all, fs::perm_options::add, ec);

  fs::directory_iterator it(dir, ec);
  const fs::directory_iterator end;

  while (!ec && it != end) {
    std::error_code item_ec;

    const fs::file_status status = it->symlink_status(item_ec);

    if (!item_ec && fs::is_directory(status)) {
      RestoreOwnerAccess(it->path());
    }

    it.increment(ec);
  }
}

/**
 * @class   ScratchDirectory
 * @brief   Listener giving each test a new working directory and taking it away again
 *
 * The suite states what a relative path means -- SyncDir opening "." for a bare file name, a link target resolved
 * against the directory holding the link rather than the working directory -- so rewriting every path as an absolute
 * one would change what is under test. Moving the working directory instead leaves every case as it is, and covers
 * the ones not yet written.
 *
 * Safe whether ctest runs each case in its own process or the binary runs them all in one: the working directory goes
 * back to where it started between cases, and the next one enters a directory of its own from there.
 */
class ScratchDirectory : public testing::EmptyTestEventListener {
 public:
  /**
   * @brief   Record the directory the process was started in
   */
  ScratchDirectory() {
    std::error_code ec;

    start_ = std::filesystem::current_path(ec);

    if (ec) {
      Fail("cannot read the working directory", ".", ec);
    }
  }

 private:
  std::filesystem::path start_;
  std::filesystem::path dir_;
  std::random_device rd_;

  /**
   * @brief   Create a directory for the test about to run and move into it
   *
   * The only place a directory is created, which is what keeps --gtest_list_tests -- run against this binary during
   * the build, to enumerate the suite -- from leaving anything behind.
   */
  void OnTestStart(const testing::TestInfo& /*test_info*/) override {
    namespace fs = std::filesystem;

    const fs::path root = start_ / kScratchRoot;

    std::error_code ec;

    fs::create_directories(root, ec);

    if (ec) {
      Fail("cannot create the scratch root", root, ec);
    }

    for (int attempt = 0; attempt < kNameAttempts; ++attempt) {
      const fs::path candidate = root / std::format("{:08x}", rd_());

      /* Created rather than tested for and then created, so that two processes drawing the same name cannot both
       * decide it is theirs */

      if (fs::create_directory(candidate, ec)) {
        dir_ = fs::canonical(candidate, ec);

        if (ec) {
          Fail("cannot resolve the scratch directory", candidate, ec);
        }

        fs::current_path(dir_, ec);

        if (ec) {
          Fail("cannot enter the scratch directory", dir_, ec);
        }

        return;
      }

      if (ec) {
        Fail("cannot create a scratch directory", candidate, ec);
      }

      /* The name was taken; drawing another one is the whole of the retry */
    }

    Fail("cannot find a free name under", root, std::make_error_code(std::errc::file_exists));
  }

  /**
   * @brief   Leave the test's directory, and remove it unless the test failed
   * @param   test_info   Test that just ran
   */
  void OnTestEnd(const testing::TestInfo& test_info) override {
    namespace fs = std::filesystem;

    std::error_code ec;

    /* Out first: Windows will not remove a directory that is somebody's working directory. It also puts the process
     * back where it started, which is what lets the next case begin from the same place this one did. */

    fs::current_path(start_, ec);

    if (ec) {
      Fail("cannot return to the starting directory", start_, ec);
    }

    const testing::TestResult* result = test_info.result();

    if (result != nullptr && result->Failed()) {
      /* Left for the post-mortem, named so it can be found. The next run draws its own names, so nothing here is in
       * its way -- which is the difference from the fixed names this harness replaces. */

      std::cerr << "test_main: " << test_info.test_suite_name() << '.' << test_info.name() << " left '" << Show(dir_)
                << "'\n";

      return;
    }

    RestoreOwnerAccess(dir_);

    fs::remove_all(dir_, ec);

    if (ec) {
      std::cerr << "test_main: warning: cannot remove '" << Show(dir_) << "': " << ec.message() << '\n';
    }

    /* The root stays, empty or not. A sibling process in a parallel run may have created it a moment ago and be about
     * to create its own directory inside it; removing it under that process fails its create_directory and aborts the
     * whole binary. Observed, not guessed at. */
  }
};

}  // namespace

/**
 * @brief   Verify the harness placed this test in an empty scratch directory of its own
 *
 * The isolation is invisible to every other case in the suite, which is the point of arranging it here, and so is its
 * absence: were the listener to stop being registered, nothing would say so until cases began interfering with each
 * other again, somewhere else and some runs later.
 */
TEST(TestIsolationTest, RunsInItsOwnEmptyScratchDirectory) {
  std::error_code ec;

  const std::filesystem::path cwd = std::filesystem::current_path(ec);

  ASSERT_FALSE(ec) << ec.message();

  EXPECT_EQ(cwd.parent_path().filename(), std::filesystem::path(kScratchRoot));
  EXPECT_TRUE(std::filesystem::is_empty(cwd, ec));
  EXPECT_FALSE(ec) << ec.message();
}

/**
 * @brief   Run the suite with each test isolated in a working directory of its own
 * @param   argc    Argument count
 * @param   argv    Argument values
 * @return  0 when every test passed
 */
int main(int argc, char** argv) {
  testing::InitGoogleTest(&argc, argv);

  /* The listener list takes ownership of what it is appended */

  testing::UnitTest::GetInstance()->listeners().Append(new ScratchDirectory());

  return RUN_ALL_TESTS();
}
