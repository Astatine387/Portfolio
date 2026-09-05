/**
 * @file    aes_gcm_test.cpp
 * @brief   Behaviour of the AES-GCM engine
 * @author  Astatine387
 */

#include <gtest/gtest.h>
#include <openssl/err.h>

#include <atomic>
#include <stdexcept>
#include <string>
#include <vector>

#include "tests/aes_gcm_fixture.h"

/* ==================================================
 * Encryption/Decryption Tests
 * ================================================== */

/**
 * @brief   Verify encryption and decryption round-trip preserves data
 */
TEST_F(AesGcmTest, EncryptDecryptBasic) {
  const auto salt = MakeSalt(0xA5);
  const std::vector<uint8_t> orig = ToBytes("Hello, world!");
  std::vector<uint8_t> copy;

  EXPECT_EQ(DecryptBytes(EncryptBytes(orig, salt, "password"), copy, salt, "password"), Result::kSuccess);
  EXPECT_EQ(copy, orig);
}

/**
 * @brief   Verify encryption is deterministic, since the nonce is derived from the chunk counter
 */
TEST_F(AesGcmTest, EncryptIsDeterministic) {
  const auto salt = MakeSalt(0xA5);
  const std::vector<uint8_t> orig = ToBytes("Hello, world!");
  const std::vector<uint8_t> copy1 = EncryptBytes(orig, salt, "password");
  const std::vector<uint8_t> copy2 = EncryptBytes(orig, salt, "password");

  EXPECT_FALSE(copy1.empty());
  EXPECT_EQ(copy1, copy2);
}

/**
 * @brief   Verify a reused AesGcm can encrypt twice with one object
 *
 * The freeing of the previous context is not observable from here: leaking it would make
 * both calls succeed just the same. What actually catches that is LeakSanitizer in the
 * ASan build, which fails this test at process exit.
 */
TEST_F(AesGcmTest, ReuseFreesPreviousContext) {
  AesGcm aes;
  const auto salt = MakeSalt(0xA5);
  const SecureKey& key = MakeKey("password", salt);

  Store(src_path_, ToBytes("Hello, world!"));

  {
    FilePair files(src_path_, enc_path_);

    EXPECT_EQ(aes.Encrypt(files.Src(), files.Dst(), key, salt, MinParams()), Result::kSuccess);
  }

  {
    FilePair files(src_path_, dec_path_);

    EXPECT_EQ(aes.Encrypt(files.Src(), files.Dst(), key, salt, MinParams()), Result::kSuccess);
  }
}

/* ==================================================
 * Header Tests
 * ================================================== */

/**
 * @brief   Verify encryption records the magic number and the parameters it was given
 */
TEST_F(AesGcmTest, EncryptWritesHeader) {
  FileHeader header;
  FILE* file = nullptr;
  const auto salt = MakeSalt(0xA5);

  EncryptBytes(ToBytes("Hello, world!"), salt, "password");

  /* The header must describe the salt and the parameters the caller derived with */

  OpenFile(&file, enc_path_, "rb");

  ASSERT_NE(file, nullptr);
  EXPECT_EQ(ReadHeader(file, header), HeaderStatus::kOk);

  fclose(file);

  EXPECT_EQ(header.chunk_log2, kChunkSizeLog2);
  EXPECT_EQ(header.params.time_cost, MinParams().time_cost);
  EXPECT_EQ(header.params.mem_cost, MinParams().mem_cost);
  EXPECT_EQ(header.params.parallelism, MinParams().parallelism);
  EXPECT_EQ(header.salt, salt);
}

/**
 * @brief   Verify a file too small to hold a header is rejected before anything is parsed
 */
TEST_F(AesGcmTest, DecryptRejectsUndersizedFile) {
  const auto salt = MakeSalt(0xA5);

  std::vector<uint8_t> copy;

  EXPECT_EQ(DecryptBytes(std::vector<uint8_t>(kMinSize - 1, 0x00), copy, salt, "password"), Result::kFailure);
  EXPECT_NE(last_error_.find("too small"), std::string::npos);
}

/**
 * @brief   Verify a file with a wrong magic number is rejected
 */
TEST_F(AesGcmTest, DecryptRejectsForeignFile) {
  const auto salt = MakeSalt(0xA5);

  std::vector<uint8_t> copy;

  EXPECT_EQ(DecryptBytes(std::vector<uint8_t>(kMinSize, 0x00), copy, salt, "password"), Result::kFailure);
  EXPECT_NE(last_error_.find("Not a FileEncryption file"), std::string::npos);
}

/* ==================================================
 * Authentication Tests
 * ================================================== */

/**
 * @brief   Verify decryption with the wrong key fails
 */
TEST_F(AesGcmTest, DecryptWrongKey) {
  const auto salt = MakeSalt(0xA5);
  const std::vector<uint8_t> cipher = EncryptBytes(ToBytes("Hello, world!"), salt, "password");
  std::vector<uint8_t> copy;

  EXPECT_EQ(DecryptBytes(cipher, copy, salt, "asdf1234"), Result::kFailure);
}

/* ==================================================
 * Callback Tests
 * ================================================== */

/**
 * @brief   Verify ReportError formats and appends queued OpenSSL errors
 */
TEST_F(AesGcmTest, ErrorCallbackFormatsQueue) {
  const auto salt = MakeSalt(0xA5);
  const std::vector<uint8_t> cipher = EncryptBytes(ToBytes("Hello, world!"), salt, "password");
  std::vector<uint8_t> copy;

  ERR_clear_error();
  ERR_raise(ERR_LIB_USER, ERR_R_INTERNAL_ERROR);

  EXPECT_EQ(DecryptBytes(cipher, copy, salt, "asdf1234"), Result::kFailure);
  EXPECT_NE(last_error_.find(" -> "), std::string::npos);
}

/**
 * @brief   Verify progress is reported once per whole percent
 */
TEST_F(AesGcmTest, ProgressSkipsRepeatedPercent) {
  constexpr size_t kChunks = 200;

  AesGcm aes;

  const auto salt = MakeSalt(0xA5);

  std::vector<int> res;

  Store(src_path_, MakePlain(kChunks * kChunkSize));

  aes.SetProgressCallback([&](int perc) { res.push_back(perc); });

  {
    FilePair files(src_path_, enc_path_);

    EXPECT_EQ(aes.Encrypt(files.Src(), files.Dst(), MakeKey("password", salt), salt, MinParams()), Result::kSuccess);
  }

  EXPECT_LT(res.size(), kChunks);
  EXPECT_FALSE(res.empty());

  for (size_t i = 1; i < res.size(); i++) {
    EXPECT_GT(res[i], res[i - 1]);
  }
}

/* ==================================================
 * Cancellation Tests
 * ================================================== */

/**
 * @brief   Verify cancelling an encryption aborts it promptly and reports failure
 */
TEST_F(AesGcmTest, CancelDuringEncryption) {
  AesGcm aes;
  std::atomic<bool> cancel{ false };
  int cnt = 0;
  const auto salt = MakeSalt(0xA5);

  Store(src_path_, MakePlain(kChunkSize * 10));

  aes.SetCancelFlag(&cancel);

  aes.SetProgressCallback([&](int) {
    cnt++;

    if (cnt >= 2) {
      cancel.store(true, std::memory_order_relaxed);
    }
  });

  FilePair files(src_path_, enc_path_);

  EXPECT_EQ(aes.Encrypt(files.Src(), files.Dst(), MakeKey("password", salt), salt, MinParams()), Result::kFailure);
  EXPECT_GE(cnt, 2);
  EXPECT_LE(cnt, 3);
}

/**
 * @brief   Verify cancelling partway through a decryption aborts it and leaves only whole chunks
 *
 * A drained cancellation leaves a whole number of chunks, each matching the plaintext; a write still in flight at close
 * time would leave a short or torn tail instead. These are necessary conditions, not a proof. What catches a missing
 * drain directly is ThreadSanitizer, which reports the writer thread racing the caller's close.
 */
TEST_F(AesGcmTest, CancelDuringDecryption) {
  AesGcm aes;
  std::atomic<bool> cancel{ false };
  const auto salt = MakeSalt(0xA5);
  const std::vector<uint8_t> plain = MakePlain(kChunkSize * 10);

  Store(enc_path_, EncryptBytes(plain, salt, "password"));

  aes.SetCancelFlag(&cancel);

  aes.SetProgressCallback([&](int perc) {
    if (perc > 50) {
      cancel.store(true, std::memory_order_relaxed);
    }
  });

  /* Scoped so the destination is closed before it is read back */

  {
    FilePair files(enc_path_, dec_path_);

    EXPECT_EQ(aes.Decrypt(files.Src(), files.Dst(), MakeKey("password", salt)), Result::kFailure);
  }

  std::vector<uint8_t> written;

  Read(dec_path_, written);

  EXPECT_GT(written.size(), 0U);
  EXPECT_EQ(written.size() % kChunkSize, 0U);
  EXPECT_EQ(written, std::vector<uint8_t>(plain.data(), plain.data() + written.size()));
}

/* ==================================================
 * Write Failure Tests
 * ================================================== */

/**
 * @brief   Verify a write failure raised on the writer thread stops the producer at once
 */
TEST_F(AesGcmTest, WriteFailureStopsTheProducer) {
  AesGcm aes;
  std::string res;
  constexpr size_t kChunks = 4;
  const auto salt = MakeSalt(0x00);
  int cnt = 0;

  Store(enc_path_, EncryptBytes(MakePlain(kChunks * kChunkSize), salt, "password"));
  Store(dec_path_, MakePlain(1));

  aes.SetErrorCallback([&](const char* msg) { res += msg; });
  aes.SetProgressCallback([&](int) { cnt++; });

  /* Decrypt into a read-only destination so every asynchronous write fails */

  FilePair files(enc_path_, dec_path_, "rb");

  EXPECT_EQ(aes.Decrypt(files.Src(), files.Dst(), MakeKey("password", salt)), Result::kFailure);
  EXPECT_NE(res.find("Write failed"), std::string::npos);

  EXPECT_EQ(cnt, 1);
}

/**
 * @brief   Verify a thrown error callback doesn't escape the noexcept writer thread
 */
TEST_F(AesGcmTest, ThrowingErrorCallbackDoesNotTerminate) {
  AesGcm aes;
  Result res = Result::kSuccess;
  int calls = 0;
  const auto salt = MakeSalt(0x00);

  Store(enc_path_, EncryptBytes(MakePlain(kChunkSize * 4), salt, "password"));
  Store(dec_path_, MakePlain(1));

  /* A write failure drives ReportError, and the callback throws out of the writer thread */

  aes.SetErrorCallback([&](const char*) {
    calls++;

    throw std::runtime_error("error callback failed");
  });

  FilePair files(enc_path_, dec_path_, "rb");

  EXPECT_NO_THROW(res = aes.Decrypt(files.Src(), files.Dst(), MakeKey("password", salt)));
  EXPECT_EQ(res, Result::kFailure);
  EXPECT_GT(calls, 0);
}

/**
 * @brief   Verify a single-chunk file reports a write failure raised after the last submission
 */
TEST_F(AesGcmTest, DecryptReportsWriteFailureOnFinalFlush) {
  AesGcm aes;
  std::string captured;
  const auto salt = MakeSalt(0xA5);
  const std::vector<uint8_t> cipher = EncryptBytes(MakePlain(kChunkSize), salt, "password");

  ASSERT_EQ(cipher.size(), kHeaderSize + kChunkSize + kTagSize);

  Store(enc_path_, cipher);
  Store(dec_path_, MakePlain(1));

  aes.SetErrorCallback([&](const char* msg) { captured += msg; });

  FilePair files(enc_path_, dec_path_, "rb");

  EXPECT_EQ(aes.Decrypt(files.Src(), files.Dst(), MakeKey("password", salt)), Result::kFailure);
  EXPECT_NE(captured.find("Write failed"), std::string::npos);
}

/**
 * @brief   Verify a destination that cannot be written to fails the encryption
 */
TEST_F(AesGcmTest, EncryptReportsWriteFailure) {
  AesGcm aes;
  std::string captured;
  const auto salt = MakeSalt(0xA5);
  const std::vector<uint8_t> plain = MakePlain(1);

  Store(src_path_, plain);
  Store(enc_path_, plain);

  aes.SetErrorCallback([&](const char* msg) { captured += msg; });

  FilePair files(src_path_, enc_path_, "rb");

  EXPECT_EQ(aes.Encrypt(files.Src(), files.Dst(), MakeKey("password", salt), salt, MinParams()), Result::kFailure);
  EXPECT_NE(captured.find("Write failed"), std::string::npos);
}

/**
 * @brief   Verify a destination that runs out of space mid-file fails the encryption
 */
TEST_F(AesGcmTest, EncryptReportsDiskFull) {
  const auto salt = MakeSalt(0xA5);

  for (size_t chunks : { size_t{ 1 }, size_t{ 3 } }) {
    SCOPED_TRACE(testing::Message() << "chunks=" << chunks);

    AesGcm aes;
    std::string captured;

    Store(src_path_, MakePlain(chunks * kChunkSize));

    aes.SetErrorCallback([&](const char* msg) { captured += msg; });

    FilePair files(src_path_, "/dev/full", "wb");

    if (files.Dst() == nullptr) {
      GTEST_SKIP() << "/dev/full is not available";
    }

    EXPECT_EQ(aes.Encrypt(files.Src(), files.Dst(), MakeKey("password", salt), salt, MinParams()), Result::kFailure);
    EXPECT_NE(captured.find("Write failed"), std::string::npos);
  }
}
