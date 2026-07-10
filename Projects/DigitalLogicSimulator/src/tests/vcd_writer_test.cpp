/**
 * @file    vcd_writer_test.cpp
 * @brief   Unit tests for the VCD waveform writer
 * @author  Astatine387
 */

#include "parser/vcd_writer.h"

#include <gtest/gtest.h>

#include <cstddef>
#include <set>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

#include "core/kernel.h"
#include "core/logic4.h"
#include "core/netlist.h"

namespace {

/**
 * @brief     Split VCD text into individual lines
 * @param     text    VCD output to split
 * @return    One string per line, in order
 */
std::vector<std::string> Lines(const std::string& text) {
  std::vector<std::string> lines;
  std::istringstream in(text);
  std::string line;

  while (std::getline(in, line)) {
    lines.push_back(line);
  }

  return lines;
}

/**
 * @brief     Whether a line appears in the text
 * @param     text      VCD output to search
 * @param     target    Line to look for
 * @return    True if any line equals target
 */
bool HasLine(const std::string& text, std::string_view target) {
  for (const std::string& line : Lines(text)) {
    if (line == target) {
      return true;
    }
  }

  return false;
}

/**
 * @brief     Number of times a line appears in the text
 * @param     text      VCD output to search
 * @param     target    Line to count
 * @return    Count of lines equal to target
 */
int CountLine(const std::string& text, std::string_view target) {
  int count = 0;

  for (const std::string& line : Lines(text)) {
    if (line == target) {
      count++;
    }
  }

  return count;
}

/**
 * @brief     Whether a substring appears anywhere in the text
 * @param     text      VCD output to search
 * @param     needle    Substring to look for
 * @return    True if needle occurs in text
 */
bool Contains(const std::string& text, std::string_view needle) {
  return text.find(needle) != std::string::npos;
}

/**
 * @brief     Build the value-change line a scalar net would emit
 * @param     value   Value character
 * @param     code    VCD identifier code of the net
 * @return    Scalar value-change line
 */
std::string ScalarChange(char value, std::string_view code) {
  return std::string(1, value) + std::string(code);
}

}  // namespace

/* ==================================================
 * Header
 * ================================================== */

/**
 * @brief   Verify the header carries every required VCD section
 */
TEST(VcdWriterHeader, ContainsRequiredSections) {
  Netlist net;

  net.AddInput("a");
  net.AddInput("b");
  net.AddOutput("y");

  std::ostringstream out;
  VcdWriter vcd(net, out);

  vcd.WriteHeader();

  const std::string text = out.str();

  EXPECT_TRUE(Contains(text, "$version"));
  EXPECT_TRUE(Contains(text, "$timescale"));
  EXPECT_TRUE(Contains(text, "$scope module top"));
  EXPECT_TRUE(Contains(text, "$upscope"));
  EXPECT_TRUE(Contains(text, "$enddefinitions"));
}

/**
 * @brief   Verify no $date is emitted so runs stay byte-identical
 */
TEST(VcdWriterHeader, OmitsDateForDeterminism) {
  Netlist net;

  net.AddInput("a");

  std::ostringstream out;
  VcdWriter vcd(net, out);

  vcd.WriteHeader();

  EXPECT_FALSE(Contains(out.str(), "$date"));
}

/**
 * @brief   Verify the module name and timescale arguments reach the header
 */
TEST(VcdWriterHeader, UsesGivenModuleAndTimescale) {
  Netlist net;

  net.AddInput("a");

  std::ostringstream out;
  VcdWriter vcd(net, out, "full_adder", "10ps");

  vcd.WriteHeader();

  const std::string text = out.str();

  EXPECT_TRUE(Contains(text, "$scope module full_adder"));
  EXPECT_TRUE(Contains(text, "$timescale 10ps"));
}

/**
 * @brief   Verify exactly one $var line is declared per net
 */
TEST(VcdWriterHeader, DeclaresEveryNetOnce) {
  Netlist net;

  net.AddInput("a");
  net.AddInput("b");
  net.AddOutput("y");
  net.AddWire("w");

  std::ostringstream out;
  VcdWriter vcd(net, out);

  vcd.WriteHeader();

  int var_lines = 0;

  for (const std::string& line : Lines(out.str())) {
    if (line.starts_with("$var ")) {
      var_lines++;
    }
  }

  EXPECT_EQ(var_lines, static_cast<int>(net.NumNets()));
}

/**
 * @brief   Verify a second WriteHeader call writes nothing
 */
TEST(VcdWriterHeader, WriteHeaderIsIdempotent) {
  Netlist net;

  net.AddInput("a");
  net.AddOutput("y");

  std::ostringstream out0;
  VcdWriter vcd0(net, out0);

  vcd0.WriteHeader();

  std::ostringstream out1;
  VcdWriter vcd1(net, out1);

  vcd1.WriteHeader();
  vcd1.WriteHeader();

  EXPECT_EQ(out0.str(), out1.str());
}

/**
 * @brief   Verify identical inputs produce identical output across runs
 */
TEST(VcdWriterHeader, OutputIsDeterministic) {
  using enum Logic4;

  const auto emit = []() -> std::string {
    Netlist net;
    const NetId a = net.AddInput("a");
    const NetId y = net.AddOutput("y");

    net.AddGate(GateType::kBuf, { a }, y);

    std::ostringstream out;
    VcdWriter vcd(net, out, "m");

    vcd.WriteHeader();
    vcd.OnValueChange(0, a, k1);
    vcd.OnValueChange(1, y, k1);
    vcd.Finish(2);

    return out.str();
  };

  EXPECT_EQ(emit(), emit());
}

/* ==================================================
 * Identifier codes
 * ================================================== */

/**
 * @brief   Verify every identifier code is non-empty printable ASCII
 */
TEST(VcdWriterCode, AssignsPrintableAsciiCodes) {
  Netlist net;

  for (std::size_t i = 0; i < kIdCodeRadix * kIdCodeRadix; i++) {
    net.AddWire("w" + std::to_string(i));
  }

  std::ostringstream out;
  VcdWriter vcd(net, out);

  for (std::size_t i = 0; i < net.NumNets(); i++) {
    const std::string_view code = vcd.Code(MakeNetId(i));

    EXPECT_FALSE(code.empty());

    for (const char c : code) {
      EXPECT_GE(c, kFirstIdCode);
      EXPECT_LE(c, kLastIdCode);
    }
  }
}

/**
 * @brief   Verify identifier codes stay unique past the base-94 rollover
 */
TEST(VcdWriterCode, CodesAreUnique) {
  Netlist net;

  for (std::size_t i = 0; i < kIdCodeRadix * kIdCodeRadix; ++i) {
    net.AddWire("w" + std::to_string(i));
  }

  std::ostringstream out;
  VcdWriter vcd(net, out);

  std::set<std::string> seen;

  for (std::size_t i = 0; i < net.NumNets(); ++i) {
    seen.insert(std::string(vcd.Code(MakeNetId(i))));
  }

  EXPECT_EQ(seen.size(), net.NumNets());
}

/**
 * @brief   Verify codes roll to two characters exactly at the radix boundary
 */
TEST(VcdWriterCode, RollsOverBeyondRadix) {
  Netlist net;

  for (std::size_t i = 0; i < kIdCodeRadix * kIdCodeRadix; i++) {
    net.AddWire("w" + std::to_string(i));
  }

  std::ostringstream out;
  VcdWriter vcd(net, out);

  EXPECT_EQ(vcd.Code(MakeNetId(0)), "!");
  EXPECT_EQ(vcd.Code(MakeNetId(kIdCodeRadix - 1)), "~");
  EXPECT_EQ(vcd.Code(MakeNetId(kIdCodeRadix)).size(), 2u);
}

/* ==================================================
 * Signal names
 * ================================================== */

/**
 * @brief   Verify declared net names are used verbatim
 */
TEST(VcdWriterName, KeepsDeclaredNames) {
  Netlist net;

  const NetId clk = net.AddInput("clk");
  const NetId q = net.AddOutput("q");

  std::ostringstream out;
  VcdWriter vcd(net, out);

  EXPECT_EQ(vcd.Name(clk), "clk");
  EXPECT_EQ(vcd.Name(q), "q");
}

/**
 * @brief   Verify anonymous nets receive a synthesized _n<index> name
 */
TEST(VcdWriterName, SynthesizesNamesForAnonymousNets) {
  Netlist net;

  net.AddInput("a");

  const NetId anon = net.AddWire();
  std::ostringstream out;
  VcdWriter vcd(net, out);

  EXPECT_EQ(vcd.Name(anon), "_n" + std::to_string(Index(anon)));
}

/* ==================================================
 * Initial dump
 * ================================================== */

/**
 * @brief   Verify the initial values sit inside a #0 $dumpvars block
 */
TEST(VcdWriterDump, WrapsInitialValuesInDumpvars) {
  Netlist net;

  net.AddInput("a");

  std::ostringstream out;
  VcdWriter vcd(net, out);

  vcd.WriteHeader();

  const std::string text = out.str();

  EXPECT_TRUE(HasLine(text, "#0"));
  EXPECT_TRUE(HasLine(text, "$dumpvars"));
  EXPECT_TRUE(HasLine(text, "$end"));
}

/**
 * @brief   Verify every net is dumped as X at time 0
 */
TEST(VcdWriterDump, InitializesEveryNetToX) {
  Netlist net;
  const NetId a = net.AddInput("a");
  const NetId b = net.AddInput("b");
  const NetId y = net.AddOutput("y");

  std::ostringstream out;
  VcdWriter vcd(net, out);

  vcd.WriteHeader();

  const std::string text = out.str();

  EXPECT_TRUE(HasLine(text, ScalarChange('x', vcd.Code(a))));
  EXPECT_TRUE(HasLine(text, ScalarChange('x', vcd.Code(b))));
  EXPECT_TRUE(HasLine(text, ScalarChange('x', vcd.Code(y))));
}

/* ==================================================
 * Value changes
 * ================================================== */

/**
 * @brief   Verify each value maps to its VCD character with no separating space
 */
TEST(VcdWriterValueChange, EmitsZeroOneAndZWithoutSpace) {
  using enum Logic4;

  Netlist net;
  const NetId n0 = net.AddWire("n0");
  const NetId n1 = net.AddWire("n1");
  const NetId nz = net.AddWire("nz");

  std::ostringstream out;
  VcdWriter vcd(net, out);

  vcd.WriteHeader();
  vcd.OnValueChange(1, n0, k0);
  vcd.OnValueChange(1, n1, k1);
  vcd.OnValueChange(1, nz, kZ);

  const std::string text = out.str();

  EXPECT_TRUE(HasLine(text, ScalarChange('0', vcd.Code(n0))));
  EXPECT_TRUE(HasLine(text, ScalarChange('1', vcd.Code(n1))));
  EXPECT_TRUE(HasLine(text, ScalarChange('z', vcd.Code(nz))));
}

/**
 * @brief   Verify a value change before WriteHeader writes the header first
 */
TEST(VcdWriterValueChange, WritesHeaderLazilyOnFirstChange) {
  using enum Logic4;

  Netlist net;
  const NetId n = net.AddWire("n");

  std::ostringstream out;
  VcdWriter vcd(net, out);

  vcd.OnValueChange(1, n, k1);

  const std::string text = out.str();

  EXPECT_TRUE(Contains(text, "$enddefinitions"));
  EXPECT_TRUE(Contains(text, "$dumpvars"));
  EXPECT_TRUE(HasLine(text, ScalarChange('1', vcd.Code(n))));
}

/* ==================================================
 * Time markers
 * ================================================== */

/**
 * @brief   Verify changes sharing a time emit a single time marker
 */
TEST(VcdWriterTimeMarker, SameTimeEmitsSingleMarker) {
  using enum Logic4;

  Netlist net;
  const NetId a = net.AddWire("a");
  const NetId b = net.AddWire("b");

  std::ostringstream out;
  VcdWriter vcd(net, out);

  vcd.WriteHeader();
  vcd.OnValueChange(5, a, k1);
  vcd.OnValueChange(5, b, k0);

  EXPECT_EQ(CountLine(out.str(), "#5"), 1);
}

/**
 * @brief   Verify advancing the time emits a fresh marker
 */
TEST(VcdWriterTimeMarker, AdvancingTimeEmitsNewMarker) {
  using enum Logic4;

  Netlist net;
  const NetId a = net.AddWire("a");

  std::ostringstream out;
  VcdWriter vcd(net, out);

  vcd.WriteHeader();
  vcd.OnValueChange(1, a, k1);
  vcd.OnValueChange(2, a, k0);

  const std::string text = out.str();

  EXPECT_TRUE(HasLine(text, "#1"));
  EXPECT_TRUE(HasLine(text, "#2"));
}

/**
 * @brief   Verify a change at time 0 does not repeat the header's #0 marker
 */
TEST(VcdWriterTimeMarker, ChangeAtTimeZeroDoesNotRepeatMarker) {
  using enum Logic4;

  Netlist net;
  const NetId a = net.AddWire("a");

  std::ostringstream out;
  VcdWriter vcd(net, out);

  vcd.WriteHeader();
  vcd.OnValueChange(0, a, k1);

  EXPECT_EQ(CountLine(out.str(), "#0"), 1);
}

/* ==================================================
 * Finish
 * ================================================== */

/**
 * @brief   Verify Finish extends the waveform past the last change
 */
TEST(VcdWriterFinish, ExtendsWaveformPastLastChange) {
  using enum Logic4;

  Netlist net;
  const NetId a = net.AddWire("a");

  std::ostringstream out;
  VcdWriter vcd(net, out);

  vcd.WriteHeader();
  vcd.OnValueChange(1, a, k1);
  vcd.Finish(5);

  EXPECT_TRUE(HasLine(out.str(), "#5"));
}

/**
 * @brief   Verify Finish adds no marker when the end equals the last change
 */
TEST(VcdWriterFinish, NoExtraMarkerWhenEndEqualsLastChange) {
  using enum Logic4;

  Netlist net;
  const NetId a = net.AddWire("a");

  std::ostringstream out;
  VcdWriter vcd(net, out);

  vcd.WriteHeader();
  vcd.OnValueChange(1, a, k1);
  vcd.Finish(1);

  EXPECT_EQ(CountLine(out.str(), "#1"), 1);
}

/**
 * @brief   Verify Finish on a run with no changes still writes the header
 */
TEST(VcdWriterFinish, WritesHeaderForEmptyRun) {
  Netlist net;
  net.AddInput("a");

  std::ostringstream out;
  VcdWriter vcd(net, out);

  vcd.Finish(0);

  const std::string text = out.str();

  EXPECT_TRUE(Contains(text, "$enddefinitions"));
  EXPECT_TRUE(Contains(text, "$dumpvars"));
}

/* ==================================================
 * End-to-end with the kernel
 * ================================================== */

/**
 * @brief   Verify the writer records a real full-adder run driven by the kernel
 */
TEST(VcdWriterEndToEnd, RecordsFullAdderRun) {
  using enum Logic4;

  Netlist net;
  const NetId a = net.AddInput("a");
  const NetId b = net.AddInput("b");
  const NetId cin = net.AddInput("cin");
  const NetId sum = net.AddOutput("sum");
  const NetId cout = net.AddOutput("cout");
  const NetId w1 = net.AddWire("w1");
  const NetId w2 = net.AddWire("w2");
  const NetId w3 = net.AddWire("w3");

  net.AddGate(GateType::kXor, { a, b }, w1);
  net.AddGate(GateType::kXor, { w1, cin }, sum);
  net.AddGate(GateType::kAnd, { a, b }, w2);
  net.AddGate(GateType::kAnd, { w1, cin }, w3);
  net.AddGate(GateType::kOr, { w2, w3 }, cout);

  Kernel kernel(net);
  std::ostringstream out;
  VcdWriter vcd(net, out, "full_adder");

  vcd.WriteHeader();
  kernel.SetValueChangeCallback([&vcd](Time t, NetId n, Logic4 v) { vcd.OnValueChange(t, n, v); });

  kernel.Poke(a, k1, 0);
  kernel.Poke(b, k1, 0);
  kernel.Poke(cin, k0, 0);
  kernel.Run();
  kernel.Poke(cin, k1, 10);

  const RunResult result = kernel.Run();

  vcd.Finish(result.end_time);

  EXPECT_EQ(kernel.Value(sum), k1);
  EXPECT_EQ(kernel.Value(cout), k1);

  const std::string text = out.str();

  EXPECT_FALSE(Contains(text, "$date"));
  EXPECT_TRUE(HasLine(text, "#0"));
  EXPECT_TRUE(HasLine(text, "#10"));
  EXPECT_TRUE(HasLine(text, ScalarChange('0', vcd.Code(sum))));
  EXPECT_TRUE(HasLine(text, ScalarChange('1', vcd.Code(sum))));
  EXPECT_TRUE(HasLine(text, ScalarChange('1', vcd.Code(cout))));
}