/**
 * @file    secure_buffer_test.cpp
 * @brief   Unit tests for SecureBuffer class
 * @author  Astatine387
 */

#include "core/secure_buffer.h"

#include <gtest/gtest.h>

#include <cstdint>
#include <cstring>
#include <span>
#include <utility>

#ifndef _WIN32
#include <sodium.h>
#include <sys/resource.h>
#include <unistd.h>

#include <cstddef>

#include "common/constants.h"
#include "utils/password.h"
#endif

/* ==================================================
 * Allocation Test
 * ================================================== */

/**
 * @brief   Verify a sized buffer allocates and reports its logical size
 */
TEST(SecureBufferTest, AllocatesLogicalSize) {
  SecureBuffer buff(64);

  EXPECT_TRUE(buff.Valid());
  EXPECT_EQ(buff.Size(), 64u);
  EXPECT_NE(buff.Data(), nullptr);
}

/**
 * @brief   Verify a default buffer is empty and valid
 */
TEST(SecureBufferTest, EmptyBufferIsValid) {
  SecureBuffer buff;

  EXPECT_TRUE(buff.Valid());
  EXPECT_EQ(buff.Size(), 0u);
  EXPECT_TRUE(buff.Span().empty());
}

/* ==================================================
 * Span Test
 * ================================================== */

/**
 * @brief   Verify Span covers exactly the logical region
 */
TEST(SecureBufferTest, SpanCoversLogicalRegion) {
  SecureBuffer buff(32);

  std::span<uint8_t> span = buff.Span();

  EXPECT_EQ(span.size(), 32u);
  EXPECT_EQ(span.data(), buff.Data());
}

/**
 * @brief   Verify the const Span overload covers the logical region
 */
TEST(SecureBufferTest, ConstSpanCoversLogicalRegion) {
  SecureBuffer buff(32);
  const SecureBuffer& cbuff = buff;

  std::span<const uint8_t> span = cbuff.Span();

  EXPECT_EQ(span.size(), 32u);
  EXPECT_EQ(span.data(), cbuff.Data());
}

/* ==================================================
 * Subspan Test
 * ================================================== */

/**
 * @brief   Verify Subspan returns an in-range subrange
 */
TEST(SecureBufferTest, SubspanInRange) {
  SecureBuffer buff(32);

  auto sub = buff.Subspan(8, 16);

  ASSERT_TRUE(sub.has_value());

  std::span<uint8_t> view = sub.value();  // NOLINT(bugprone-unchecked-optional-access)

  EXPECT_EQ(view.size(), 16u);
  EXPECT_EQ(view.data(), buff.Data() + 8);
}

/**
 * @brief   Verify a whole-region Subspan is accepted
 */
TEST(SecureBufferTest, SubspanWholeRegion) {
  SecureBuffer buff(32);

  auto sub = buff.Subspan(0, 32);

  ASSERT_TRUE(sub.has_value());
  EXPECT_EQ(sub.value().size(), 32u);  // NOLINT(bugprone-unchecked-optional-access)
}

/**
 * @brief   Verify Subspan rejects a range that runs past the end
 */
TEST(SecureBufferTest, SubspanPastEnd) {
  SecureBuffer buff(32);

  EXPECT_FALSE(buff.Subspan(16, 20).has_value());  // 16 + 20 > 32
  EXPECT_FALSE(buff.Subspan(33, 0).has_value());   // Offset past the end
}

/**
 * @brief   Verify Subspan rejects a length that overflows the offset
 */
TEST(SecureBufferTest, SubspanOverflow) {
  SecureBuffer buff(32);

  EXPECT_FALSE(buff.Subspan(8, SIZE_MAX).has_value());
}

/**
 * @brief   Verify the const Subspan overload is bounds-checked
 */
TEST(SecureBufferTest, ConstSubspanChecked) {
  SecureBuffer buff(32);
  const SecureBuffer& cbuff = buff;

  auto ok = cbuff.Subspan(0, 32);

  ASSERT_TRUE(ok.has_value());
  EXPECT_EQ(ok.value().size(), 32u);  // NOLINT(bugprone-unchecked-optional-access)

  EXPECT_FALSE(cbuff.Subspan(1, 32).has_value());
}

/* ==================================================
 * Move Test
 * ================================================== */

/**
 * @brief   Verify the move constructor transfers ownership without reallocating
 */
TEST(SecureBufferTest, MoveConstructTransfersOwnership) {
  SecureBuffer src(32);

  ASSERT_TRUE(src.Valid());
  ASSERT_NE(src.Data(), nullptr);

  memset(src.Data(), 0xAB, 32);

  const uint8_t* data = src.Data();

  SecureBuffer dst(std::move(src));

  EXPECT_EQ(dst.Data(), data);  // Same allocation, not a copy
  EXPECT_EQ(dst.Size(), 32u);
  EXPECT_TRUE(dst.Valid());
  EXPECT_EQ(dst.Data()[0], 0xAB);  // Contents survive the move
}

/**
 * @brief   Verify the moved-from buffer is left empty and safely destructible
 */
TEST(SecureBufferTest, MoveConstructClearsSource) {
  SecureBuffer src(32);

  ASSERT_TRUE(src.Valid());

  SecureBuffer dst(std::move(src));

  /* Inspecting the moved-from object is the point of this test */

  // NOLINTBEGIN(bugprone-use-after-move)
  EXPECT_EQ(src.Data(), nullptr);
  EXPECT_EQ(src.Size(), 0u);
  EXPECT_TRUE(src.Valid());
  EXPECT_TRUE(src.Span().empty());
  // NOLINTEND(bugprone-use-after-move)
}

/**
 * @brief   Verify move-constructing from an empty buffer works
 */
TEST(SecureBufferTest, MoveConstructEmptyBuffer) {
  SecureBuffer src;
  SecureBuffer dst(std::move(src));

  EXPECT_EQ(dst.Size(), 0u);
  EXPECT_EQ(dst.Data(), nullptr);
  EXPECT_TRUE(dst.Valid());
}

/**
 * @brief   Verify self-move-assignment leaves the buffer intact
 */
TEST(SecureBufferTest, SelfMoveAssign) {
  SecureBuffer buff(32);

  const uint8_t* addr = buff.Data();
  SecureBuffer& ref = buff;

  buff = std::move(ref);

  EXPECT_EQ(buff.Data(), addr);
  EXPECT_EQ(buff.Size(), 32u);
  EXPECT_TRUE(buff.Valid());
}

#ifndef _WIN32

/* ==================================================
 * Lock Budget Test
 * ================================================== */

namespace {

/**
 * @class   MemlockLimit
 * @brief   Holds RLIMIT_MEMLOCK at a chosen soft limit for as long as it is in scope
 *
 * The limit has to go back up however the test leaves, including through the return an ASSERT makes, or every case
 * that runs afterwards inherits a process that can lock less than the one it was written against.
 */
class MemlockLimit {
 public:
  explicit MemlockLimit(rlim_t soft) {
    ok_ = getrlimit(RLIMIT_MEMLOCK, &saved_) == 0;

    if (!ok_) {
      return;  // LCOV_EXCL_LINE  getrlimit on a valid resource does not fail
    }

    rlimit next = saved_;

    next.rlim_cur = soft;
    ok_ = setrlimit(RLIMIT_MEMLOCK, &next) == 0;
  }

  ~MemlockLimit() {
    if (ok_) {
      static_cast<void>(setrlimit(RLIMIT_MEMLOCK, &saved_));
    }
  }

  MemlockLimit(const MemlockLimit&) = delete;
  MemlockLimit& operator=(const MemlockLimit&) = delete;
  MemlockLimit(MemlockLimit&&) = delete;
  MemlockLimit& operator=(MemlockLimit&&) = delete;

  [[nodiscard]] bool Ok() const { return ok_; }

 private:
  rlimit saved_{};
  bool ok_ = false;
};

/**
 * @brief   Report whether a region is already held in locked memory
 * @param   data  Start of the region
 * @param   size  Region size in bytes
 * @return  true when the region is locked
 *
 * There is nothing to ask. sodium_malloc does not report a refused mlock, which is the whole reason the ceiling is a
 * constant rather than a check, so the question is put to the kernel instead: mlock over pages that are already
 * locked costs nothing against RLIMIT_MEMLOCK and returns 0, while the same call over pages that are not has to
 * charge them against a budget this test has already spent, and is refused.
 */
bool Locked(const uint8_t* data, size_t size) {
  return sodium_mlock(const_cast<uint8_t*>(data), size) == 0;
}

}  // namespace

/**
 * @brief   Verify both images an edit holds at once stay locked inside the budget kMaxSize is sized against
 *
 * CreateEntry builds the candidate image while the installed one is still held, so the peak is the pair of them, and
 * the candidate stands kMaxEntrySize above the image it replaces because it is allocated before CommitImage has had
 * anything to say about its size. Allocated here in that shape, beside the session key and the Password buffers a
 * dialog holds, against the same RLIMIT_MEMLOCK the static_assert in constants.h assumes. A ceiling raised past the
 * budget reports nothing on its own: the pages simply stop being pinned, and a session image carries every entry
 * password in the vault.
 *
 * Skipped as root, which locks memory under CAP_IPC_LOCK and never consults the limit this case lowers.
 */
TEST(SecureBufferTest, BothEditImagesStayLockedWithinBudget) {
  if (geteuid() == 0) {
    GTEST_SKIP() << "RLIMIT_MEMLOCK does not bind root";
  }

  /* Take the one-time libsodium init before the limit comes down. It raises the soft RLIMIT_MEMLOCK to the hard one,
   * so reaching it afterwards would undo the lowering below on any machine whose hard limit is the larger of the
   * two, and this case would then pass without ever having tested the budget. std::call_once keeps the first
   * SecureBuffer below from running it a second time. */

  SecureBuffer warmup(1);

  ASSERT_TRUE(warmup.Valid());

  /* A machine whose hard limit is under the budget cannot be held at it, and lowering to whatever it does allow
   * would test a ceiling constants.h was never sized against. Read before the limit moves, so the figure is the one
   * the process actually started with. */

  rlimit current{};

  ASSERT_EQ(getrlimit(RLIMIT_MEMLOCK, &current), 0);

  if (current.rlim_max < static_cast<rlim_t>(kLockBudget)) {
    GTEST_SKIP() << "Hard RLIMIT_MEMLOCK is below the budget kMaxSize is sized against";
  }

  MemlockLimit limit(static_cast<rlim_t>(kLockBudget));

  ASSERT_TRUE(limit.Ok());

  /* The installed image at its ceiling, and the candidate an insert would build beside it */

  SecureBuffer installed(static_cast<size_t>(kMaxImageSize));
  SecureBuffer candidate(static_cast<size_t>(kMaxImageSize) + kMaxEntrySize);

  /* What kLockReserve is held back for */

  SecureBuffer key(kDerivedSize);

  Password entered;
  Password confirmed;

  ASSERT_EQ(entered.SetData("password", 8), Result::kSuccess);
  ASSERT_EQ(confirmed.SetData("asdf1234", 8), Result::kSuccess);

  ASSERT_TRUE(installed.Valid());
  ASSERT_TRUE(candidate.Valid());
  ASSERT_TRUE(key.Valid());

  EXPECT_TRUE(Locked(installed.Data(), installed.Size()));
  EXPECT_TRUE(Locked(candidate.Data(), candidate.Size()));
  EXPECT_TRUE(Locked(key.Data(), key.Size()));
  EXPECT_TRUE(Locked(reinterpret_cast<const uint8_t*>(entered.GetData()), entered.GetSize()));
  EXPECT_TRUE(Locked(reinterpret_cast<const uint8_t*>(confirmed.GetData()), confirmed.GetSize()));
}

#endif /* !_WIN32 */
