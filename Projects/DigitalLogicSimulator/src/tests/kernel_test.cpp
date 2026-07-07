/**
 * @file    kernel_test.cpp
 * @brief   Unit tests for the event-driven, 4-state simulation kernel
 * @author  Astatine387
 */

#include "core/kernel.h"

#include <gtest/gtest.h>

#include <cstddef>
#include <utility>
#include <vector>

namespace {

/**
 * @struct  FullAdder
 * @brief   A full-adder netlist
 */
struct FullAdder {
  Netlist net;  // the built netlist
  NetId a;      // addend input
  NetId b;      // addend input
  NetId cin;    // carry input
  NetId sum;    // sum output
  NetId cout;   // carry output
};

/**
 * @brief   Build the structural full-adder
 * @return  The netlist and its boundary handles
 */
FullAdder MakeFullAdder() {
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

  return FullAdder{ std::move(net), a, b, cin, sum, cout };
}

/**
 * @struct  Change
 * @brief   One recorded value-change callback, for trace comparisons
 */
struct Change {
  Time time;     // time of the change
  NetId net;     // net that changed
  Logic4 value;  // new value
};

}  // namespace

/* ==================================================
 * Initial state
 * ================================================== */

/**
 * @brief   Verify every net starts at X before any stimulus is applied
 */
TEST(KernelInit, EveryNetStartsAtX) {
  using enum Logic4;

  Netlist net;
  const NetId a = net.AddInput("a");
  const NetId b = net.AddInput("b");
  const NetId y = net.AddOutput("y");

  net.AddGate(GateType::kAnd, { a, b }, y);

  const Kernel kernel(net);

  EXPECT_EQ(kernel.Value(a), kX);
  EXPECT_EQ(kernel.Value(b), kX);
  EXPECT_EQ(kernel.Value(y), kX);
  EXPECT_EQ(kernel.Now(), 0u);
}

/**
 * @brief   Verify a run with no stimulus settles immediately and changes nothing
 */
TEST(KernelInit, NoStimulusIsQuiescent) {
  Netlist net;
  const NetId in = net.AddInput("in");
  const NetId out = net.AddOutput("out");

  net.AddGate(GateType::kBuf, { in }, out);

  Kernel kernel(net);
  const RunResult result = kernel.Run();

  EXPECT_EQ(result.status, RunStatus::kQuiescent);
  EXPECT_EQ(result.value_changes, 0u);
  EXPECT_EQ(kernel.Now(), 0u);
}

/* ==================================================
 * Combinational evaluation
 * ================================================== */

/**
 * @brief   Verify a buffer propagates its input, treating Z on the input as X
 */
TEST(KernelCombinational, Buffer) {
  using enum Logic4;

  Netlist net;
  const NetId in = net.AddInput("in");
  const NetId out = net.AddOutput("out");

  net.AddGate(GateType::kBuf, { in }, out);

  const auto drive = [&](Logic4 value) {
    Kernel kernel(net);

    kernel.Poke(in, value, 0);
    kernel.Run();

    return kernel.Value(out);
  };

  EXPECT_EQ(drive(k0), k0);
  EXPECT_EQ(drive(k1), k1);
  EXPECT_EQ(drive(kX), kX);
  EXPECT_EQ(drive(kZ), kX);
}

/**
 * @brief   Verify a two-input AND, including X-propagation and absorbing zero
 */
TEST(KernelCombinational, AndGate) {
  using enum Logic4;

  Netlist net;
  const NetId a = net.AddInput("a");
  const NetId b = net.AddInput("b");
  const NetId y = net.AddOutput("y");

  net.AddGate(GateType::kAnd, { a, b }, y);

  const auto drive = [&](Logic4 av, Logic4 bv) {
    Kernel kernel(net);

    kernel.Poke(a, av, 0);
    kernel.Poke(b, bv, 0);
    kernel.Run();

    return kernel.Value(y);
  };

  EXPECT_EQ(drive(k0, k0), k0);
  EXPECT_EQ(drive(k0, k1), k0);
  EXPECT_EQ(drive(k1, k1), k1);
  EXPECT_EQ(drive(k1, kX), kX);
  EXPECT_EQ(drive(k0, kX), k0);
}

/**
 * @brief   Verify the input fold handles gates with more than two inputs
 */
TEST(KernelCombinational, MultiInputAnd) {
  using enum Logic4;

  Netlist net;
  const NetId a = net.AddInput("a");
  const NetId b = net.AddInput("b");
  const NetId c = net.AddInput("c");
  const NetId y = net.AddOutput("y");

  net.AddGate(GateType::kAnd, { a, b, c }, y);

  const auto drive = [&](Logic4 av, Logic4 bv, Logic4 cv) {
    Kernel kernel(net);

    kernel.Poke(a, av, 0);
    kernel.Poke(b, bv, 0);
    kernel.Poke(c, cv, 0);
    kernel.Run();

    return kernel.Value(y);
  };

  EXPECT_EQ(drive(k1, k1, k1), k1);
  EXPECT_EQ(drive(k1, k1, k0), k0);
  EXPECT_EQ(drive(k1, k1, kX), kX);
  EXPECT_EQ(drive(k1, k0, kX), k0);
}

/**
 * @brief   Verify the full-adder is correct for every input
 */
TEST(KernelCombinational, FullAdderTruthTable) {
  using enum Logic4;

  const FullAdder fa = MakeFullAdder();

  for (int i = 0; i < 8; i++) {
    const Logic4 a = (i & 0b001) != 0 ? k1 : k0;
    const Logic4 b = (i & 0b010) != 0 ? k1 : k0;
    const Logic4 cin = (i & 0b100) != 0 ? k1 : k0;

    Kernel kernel(fa.net);

    kernel.Poke(fa.a, a, 0);
    kernel.Poke(fa.b, b, 0);
    kernel.Poke(fa.cin, cin, 0);

    const RunResult result = kernel.Run();

    const int ones = (i & 1) + ((i >> 1) & 1) + ((i >> 2) & 1);
    const Logic4 expected_sum = (ones & 1) != 0 ? k1 : k0;
    const Logic4 expected_cout = ones >= 2 ? k1 : k0;

    EXPECT_EQ(kernel.Value(fa.sum), expected_sum) << "input combination " << i;
    EXPECT_EQ(kernel.Value(fa.cout), expected_cout) << "input combination " << i;
    EXPECT_EQ(result.status, RunStatus::kQuiescent);
  }
}

/* ==================================================
 * Sequential evaluation (D flip-flop)
 * ================================================== */

/**
 * @brief   Verify a D flip-flop captures D on a rising clock edge
 */
TEST(KernelSequential, DffLatchesOnRisingEdge) {
  using enum Logic4;

  Netlist net;
  const NetId d = net.AddInput("d");
  const NetId clk = net.AddInput("clk");
  const NetId q = net.AddOutput("q");

  net.AddDff(d, clk, q);

  Kernel kernel(net);

  kernel.Poke(clk, k0, 0);
  kernel.Poke(d, k1, 5);
  kernel.Poke(clk, k1, 10);

  kernel.Run(9);
  EXPECT_EQ(kernel.Value(q), kX);

  kernel.Run();
  EXPECT_EQ(kernel.Value(q), k1);
}

/**
 * @brief   Verify a D flip-flop holds its value with no rising edge
 */
TEST(KernelSequential, DffHoldsWithoutRisingEdge) {
  using enum Logic4;

  Netlist net;
  const NetId d = net.AddInput("d");
  const NetId clk = net.AddInput("clk");
  const NetId q = net.AddOutput("q");

  net.AddDff(d, clk, q);

  Kernel kernel(net);

  kernel.Poke(clk, k0, 0);
  kernel.Poke(d, k1, 5);
  kernel.Run();

  EXPECT_EQ(kernel.Value(q), kX);
}

/**
 * @brief   Verify a falling edge does not capture D
 */
TEST(KernelSequential, FallingEdgeDoesNotCaptureD) {
  using enum Logic4;

  Netlist net;
  const NetId d = net.AddInput("d");
  const NetId clk = net.AddInput("clk");
  const NetId q = net.AddOutput("q");

  net.AddDff(d, clk, q);

  Kernel kernel(net);

  kernel.Poke(clk, k0, 0);
  kernel.Poke(d, k1, 5);
  kernel.Poke(clk, k1, 10);  // rising edge: Q <= 1
  kernel.Poke(d, k0, 20);    // data change with no edge
  kernel.Poke(clk, k0, 30);  // falling edge: no capture
  kernel.Poke(clk, k1, 40);  // rising edge: Q <= 0

  kernel.Run(35);
  EXPECT_EQ(kernel.Value(q), k1);

  kernel.Run();
  EXPECT_EQ(kernel.Value(q), k0);
}

/**
 * @brief   Verify an uninitialized toggle loop stays X (4-state pessimism)
 */
TEST(KernelSequential, UninitializedFeedbackStaysX) {
  using enum Logic4;

  Netlist net;
  const NetId clk = net.AddInput("clk");
  const NetId q = net.AddOutput("q");
  const NetId d = net.AddWire("d");

  net.AddGate(GateType::kNot, { q }, d);  // d = ~q
  net.AddDff(d, clk, q);                  // toggle on each rising edge

  Kernel kernel(net);

  for (const Time edge : { 10, 20, 30, 40 }) {
    kernel.Poke(clk, k0, edge - 5);
    kernel.Poke(clk, k1, edge);
  }

  kernel.Run();

  EXPECT_EQ(kernel.Value(q), kX);
}

/* ==================================================
 * Timing and scheduling
 * ================================================== */

/**
 * @brief   Verify a gate delay advances simulation time to the settle point
 */
TEST(KernelTiming, GateDelayAdvancesTime) {
  Netlist net;
  const NetId in = net.AddInput("in");
  const NetId out = net.AddOutput("out");

  net.AddGate(GateType::kBuf, { in }, out, 10);

  Kernel kernel(net);

  kernel.Poke(in, Logic4::k1, 0);

  const RunResult result = kernel.Run();

  EXPECT_EQ(kernel.Value(out), Logic4::k1);
  EXPECT_EQ(result.end_time, 10u);
  EXPECT_EQ(kernel.Now(), 10u);
  EXPECT_EQ(result.status, RunStatus::kQuiescent);
}

/**
 * @brief   Verify an output only appears once its gate delay has elapsed
 */
TEST(KernelTiming, OutputAppearsAfterDelay) {
  Netlist net;
  const NetId in = net.AddInput("in");
  const NetId out = net.AddOutput("out");

  net.AddGate(GateType::kBuf, { in }, out, 5);

  Kernel kernel(net);

  kernel.Poke(in, Logic4::k1, 0);

  kernel.Run(4);
  EXPECT_EQ(kernel.Value(out), Logic4::kX);  // before the delay elapses

  kernel.Run(5);
  EXPECT_EQ(kernel.Value(out), Logic4::k1);  // exactly at the delay
}

/**
 * @brief   Verify a bounded run applies events up to the limit and defers the rest
 */
TEST(KernelTiming, RunUntilLeavesLaterEventsPending) {
  using enum Logic4;

  Netlist net;
  const NetId a = net.AddInput("a");
  const NetId b = net.AddInput("b");
  const NetId ya = net.AddOutput("ya");
  const NetId yb = net.AddOutput("yb");

  net.AddGate(GateType::kBuf, { a }, ya);
  net.AddGate(GateType::kBuf, { b }, yb);

  Kernel kernel(net);

  kernel.Poke(a, k1, 10);
  kernel.Poke(b, k1, 20);

  const RunResult first = kernel.Run(15);

  EXPECT_EQ(first.status, RunStatus::kTimeLimit);
  EXPECT_EQ(kernel.Now(), 15u);
  EXPECT_EQ(kernel.Value(ya), k1);  // a's effect has landed
  EXPECT_EQ(kernel.Value(yb), kX);  // b's effect is still queued

  const RunResult second = kernel.Run();

  EXPECT_EQ(second.status, RunStatus::kQuiescent);
  EXPECT_EQ(kernel.Value(yb), k1);
}

/* ==================================================
 * Multi-driver resolution
 * ================================================== */

/**
 * @brief   Verify two drivers agreeing on a value pass it through
 */
TEST(KernelResolution, AgreeingDriversPassThrough) {
  using enum Logic4;

  Netlist net;
  const NetId a = net.AddInput("a");
  const NetId b = net.AddInput("b");
  const NetId out = net.AddOutput("out");

  net.AddGate(GateType::kBuf, { a }, out);
  net.AddGate(GateType::kBuf, { b }, out);

  Kernel kernel(net);

  kernel.Poke(a, k1, 0);
  kernel.Poke(b, k1, 0);
  kernel.Run();

  EXPECT_EQ(kernel.Value(out), k1);
}

/**
 * @brief   Verify two drivers with conflicting values resolve to X (contention)
 */
TEST(KernelResolution, ConflictingDriversResolveToX) {
  using enum Logic4;

  Netlist net;
  const NetId a = net.AddInput("a");
  const NetId b = net.AddInput("b");
  const NetId out = net.AddOutput("out");

  net.AddGate(GateType::kBuf, { a }, out);
  net.AddGate(GateType::kBuf, { b }, out);

  Kernel kernel(net);

  kernel.Poke(a, k0, 0);
  kernel.Poke(b, k1, 0);
  kernel.Run();

  EXPECT_EQ(kernel.Value(out), kX);
}

/* ==================================================
 * Oscillation guard
 * ================================================== */

/**
 * @brief   Verify the delta-cycle cap halts unbounded same-time activity
 *
 * A self-starting combinational oscillation cannot arise from an all-X reset, so this drives a chain of zero-delay
 * buffers deeper than a delta cycle cap.
 */
TEST(KernelOscillation, DeltaCycleCapHalts) {
  Netlist net;
  const NetId in = net.AddInput("in");
  NetId prev = in;

  for (int i = 0; i < 8; ++i) {
    const NetId next = net.AddWire();

    net.AddGate(GateType::kBuf, { prev }, next, 0);
    prev = next;
  }

  Kernel kernel(net);

  kernel.SetMaxDeltaCycles(3);
  kernel.Poke(in, Logic4::k1, 0);

  const RunResult res = kernel.Run();

  EXPECT_EQ(res.status, RunStatus::kOscillation);
  EXPECT_FALSE(res.unstable_nets.empty());
}

/* ==================================================
 * Observation and determinism
 * ================================================== */

/**
 * @brief   Verify the callback reports each net change in deterministic order
 */
TEST(KernelObservation, ValueChangeCallbackReportsChanges) {
  using enum Logic4;

  Netlist net;
  const NetId a = net.AddInput("a");
  const NetId b = net.AddInput("b");
  const NetId y = net.AddOutput("y");

  net.AddGate(GateType::kAnd, { a, b }, y);

  std::vector<Change> changes;
  Kernel kernel(net);

  kernel.SetValueChangeCallback(
      [&](Time when, NetId net_id, Logic4 val) { changes.push_back(Change{ when, net_id, val }); });

  kernel.Poke(a, k1, 0);
  kernel.Poke(b, k1, 0);

  const RunResult res = kernel.Run();

  ASSERT_EQ(changes.size(), 3u);

  EXPECT_EQ(changes[0].time, 0u);
  EXPECT_EQ(changes[0].net, a);
  EXPECT_EQ(changes[0].value, k1);

  EXPECT_EQ(changes[1].time, 0u);
  EXPECT_EQ(changes[1].net, b);
  EXPECT_EQ(changes[1].value, k1);

  EXPECT_EQ(changes[2].time, 1u);
  EXPECT_EQ(changes[2].net, y);
  EXPECT_EQ(changes[2].value, k1);

  EXPECT_EQ(res.value_changes, 3u);
}

/**
 * @brief   Verify identical stimulus yields a bit-identical change trace
 */
TEST(KernelObservation, RepeatedRunsAreDeterministic) {
  const FullAdder fa = MakeFullAdder();

  const auto trace = [&]() {
    std::vector<Change> changes;
    Kernel kernel(fa.net);

    kernel.SetValueChangeCallback(
        [&](Time when, NetId net_id, Logic4 val) { changes.push_back(Change{ when, net_id, val }); });

    kernel.Poke(fa.a, Logic4::k1, 0);
    kernel.Poke(fa.b, Logic4::k1, 0);
    kernel.Poke(fa.cin, Logic4::k1, 0);

    kernel.Run();

    return changes;
  };

  const std::vector<Change> first = trace();
  const std::vector<Change> second = trace();

  ASSERT_EQ(first.size(), second.size());

  for (std::size_t i = 0; i < first.size(); ++i) {
    EXPECT_EQ(first[i].time, second[i].time);
    EXPECT_EQ(first[i].net, second[i].net);
    EXPECT_EQ(first[i].value, second[i].value);
  }
}