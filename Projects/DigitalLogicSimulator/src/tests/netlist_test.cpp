/**
 * @file    netlist_test.cpp
 * @brief   Unit tests for the netlist IR and programmatic builder
 * @author  Astatine387
 */

#include "core/netlist.h"

#include <gtest/gtest.h>

#include <array>
#include <cstddef>
#include <span>
#include <string>
#include <vector>

/* ==================================================
 * Handles and gate-type traits
 * ================================================== */

/**
 * @brief   Verify Index recovers the original index from a NetId/GateId handle
 */
TEST(NetlistId, IndexRoundTrip) {
  for (std::size_t i = 0; i < 100; ++i) {
    EXPECT_EQ(Index(MakeNetId(i)), i);
    EXPECT_EQ(Index(MakeGateId(i)), i);
  }
}

/**
 * @brief   Verify only kDff is classified as sequential and all gates are not
 */
TEST(NetlistGateType, OnlyDffIsSequential) {
  EXPECT_FALSE(IsSequential(GateType::kAnd));
  EXPECT_FALSE(IsSequential(GateType::kOr));
  EXPECT_FALSE(IsSequential(GateType::kNot));
  EXPECT_FALSE(IsSequential(GateType::kNand));
  EXPECT_FALSE(IsSequential(GateType::kNor));
  EXPECT_FALSE(IsSequential(GateType::kXor));
  EXPECT_FALSE(IsSequential(GateType::kXnor));
  EXPECT_FALSE(IsSequential(GateType::kBuf));
  EXPECT_TRUE(IsSequential(GateType::kDff));
}

/* ==================================================
 * Net construction
 * ================================================== */

/**
 * @brief   Verify a default-constructed netlist has no nets, gates, or boundary
 */
TEST(NetlistNet, EmptyNetlist) {
  const Netlist nl;

  EXPECT_EQ(nl.NumNets(), 0u);
  EXPECT_EQ(nl.NumGates(), 0u);
  EXPECT_TRUE(nl.PrimaryInputs().empty());
  EXPECT_TRUE(nl.PrimaryOutputs().empty());
}

/**
 * @brief   Verify net handles are assigned consecutive indices in add order
 */
TEST(NetlistNet, HandlesAreSequential) {
  Netlist nl;

  EXPECT_EQ(nl.AddInput("a"), MakeNetId(0));
  EXPECT_EQ(nl.AddOutput("y"), MakeNetId(1));
  EXPECT_EQ(nl.AddWire("w"), MakeNetId(2));
  EXPECT_EQ(nl.NumNets(), 3u);
}

/**
 * @brief   Verify each added net records its kind and its name
 */
TEST(NetlistNet, KindAndName) {
  Netlist nl;
  const NetId a = nl.AddInput("a");
  const NetId y = nl.AddOutput("y");
  const NetId w = nl.AddWire("w");

  EXPECT_EQ(nl.GetNet(a).kind, NetKind::kInput);
  EXPECT_EQ(nl.GetNet(y).kind, NetKind::kOutput);
  EXPECT_EQ(nl.GetNet(w).kind, NetKind::kWire);

  EXPECT_EQ(nl.GetNet(a).name, "a");
  EXPECT_EQ(nl.GetNet(y).name, "y");
  EXPECT_EQ(nl.GetNet(w).name, "w");
}

/**
 * @brief   Verify an anonymous is a wire with an empty name
 */
TEST(NetlistNet, AnonymousWireHasEmptyName) {
  Netlist nl;
  const NetId w = nl.AddWire();

  EXPECT_TRUE(nl.GetNet(w).name.empty());
  EXPECT_EQ(nl.GetNet(w).kind, NetKind::kWire);
}

/**
 * @brief   Verify primary I/O lists follow declaration order and exclude wires
 */
TEST(NetlistNet, PrimaryListsInDeclarationOrder) {
  Netlist nl;
  const NetId a = nl.AddInput("a");
  const NetId b = nl.AddInput("b");
  nl.AddWire("w");
  const NetId y = nl.AddOutput("y");

  EXPECT_EQ(nl.PrimaryInputs(), (std::vector<NetId>{ a, b }));
  EXPECT_EQ(nl.PrimaryOutputs(), (std::vector<NetId>{ y }));
}

/* ==================================================
 * Gate construction
 * ================================================== */

/**
 * @brief   Verify a gate stores its type, input nets, and output net
 */
TEST(NetlistGate, StoresTypeInputsOutput) {
  Netlist nl;
  const NetId a = nl.AddInput("a");
  const NetId b = nl.AddInput("b");
  const NetId y = nl.AddOutput("y");
  const GateId g = nl.AddGate(GateType::kAnd, { a, b }, y);

  EXPECT_EQ(g, MakeGateId(0));
  EXPECT_EQ(nl.NumGates(), 1u);

  const Netlist::Gate& gate = nl.GetGate(g);

  EXPECT_EQ(gate.type, GateType::kAnd);
  EXPECT_EQ(gate.output, y);
  EXPECT_EQ(gate.inputs, (std::vector<NetId>{ a, b }));
}

/**
 * @brief   Verify a gate uses the default delay unless one is supplied
 */
TEST(NetlistGate, DefaultAndCustomDelay) {
  Netlist nl;
  const NetId a = nl.AddInput("a");
  const NetId y1 = nl.AddOutput("y1");
  const NetId y2 = nl.AddOutput("y2");

  const GateId g1 = nl.AddGate(GateType::kBuf, { a }, y1);
  const GateId g2 = nl.AddGate(GateType::kBuf, { a }, y2, 7);

  EXPECT_EQ(nl.GetGate(g1).delay, kDefaultDelay);
  EXPECT_EQ(nl.GetGate(g2).delay, Time{ 7 });
}

/**
 * @brief   Verify a gate accepts more than two inputs
 */
TEST(NetlistGate, NAryInputs) {
  Netlist nl;
  const NetId a = nl.AddInput("a");
  const NetId b = nl.AddInput("b");
  const NetId c = nl.AddInput("c");
  const NetId y = nl.AddOutput("y");
  const GateId g = nl.AddGate(GateType::kAnd, { a, b, c }, y);

  EXPECT_EQ(nl.GetGate(g).inputs.size(), 3u);
  EXPECT_EQ(nl.GetGate(g).inputs, (std::vector<NetId>{ a, b, c }));
}

/**
 * @brief   Verify the span and initializer-list AddGate overloads agree
 */
TEST(NetlistGate, SpanAndInitializerListAgree) {
  Netlist nl;
  const NetId a = nl.AddInput("a");
  const NetId b = nl.AddInput("b");
  const NetId y1 = nl.AddOutput("y1");
  const NetId y2 = nl.AddOutput("y2");

  const std::array<NetId, 2> inputs = { a, b };
  const GateId g_span = nl.AddGate(GateType::kOr, std::span<const NetId>(inputs), y1);
  const GateId g_list = nl.AddGate(GateType::kOr, { a, b }, y2);

  EXPECT_EQ(nl.GetGate(g_span).inputs, nl.GetGate(g_list).inputs);
  EXPECT_EQ(nl.GetGate(g_span).type, nl.GetGate(g_list).type);
}

/**
 * @brief   Verify the Nets/Gates views expose every stored record
 */
TEST(NetlistGate, ViewsExposeAllRecords) {
  Netlist nl;
  const NetId a = nl.AddInput("a");
  const NetId y = nl.AddOutput("y");

  nl.AddGate(GateType::kNot, { a }, y);

  EXPECT_EQ(nl.Nets().size(), nl.NumNets());
  EXPECT_EQ(nl.Gates().size(), nl.NumGates());
  EXPECT_EQ(nl.Gates()[0].type, GateType::kNot);
  EXPECT_EQ(nl.Nets()[Index(a)].kind, NetKind::kInput);
}

/* ==================================================
 * Connectivity
 * ================================================== */

/**
 * @brief   Verify adding a gate wires input fanout and output drivers
 */
TEST(NetlistConnectivity, DriverAndFanoutWired) {
  Netlist nl;
  const NetId a = nl.AddInput("a");
  const NetId b = nl.AddInput("b");
  const NetId y = nl.AddOutput("y");
  const GateId g = nl.AddGate(GateType::kAnd, { a, b }, y);

  // Each input net lists the gate in its fanout
  EXPECT_EQ(nl.GetNet(a).fanout, (std::vector<GateId>{ g }));
  EXPECT_EQ(nl.GetNet(b).fanout, (std::vector<GateId>{ g }));

  // The output net lists the gate in its drivers
  EXPECT_EQ(nl.GetNet(y).drivers, (std::vector<GateId>{ g }));

  // The converse lists stay empty
  EXPECT_TRUE(nl.GetNet(a).drivers.empty());
  EXPECT_TRUE(nl.GetNet(y).fanout.empty());
}

/**
 * @brief   Verify a shared net accumulates fanout in gate-construction order
 */
TEST(NetlistConnectivity, FanoutAccumulatesAcrossGates) {
  Netlist nl;
  const NetId a = nl.AddInput("a");
  const NetId y1 = nl.AddOutput("y1");
  const NetId y2 = nl.AddOutput("y2");

  const GateId g1 = nl.AddGate(GateType::kBuf, { a }, y1);
  const GateId g2 = nl.AddGate(GateType::kNot, { a }, y2);

  EXPECT_EQ(nl.GetNet(a).fanout, (std::vector<GateId>{ g1, g2 }));
}

/**
 * @brief   Verify one net can record multiple drivers
 */
TEST(NetlistConnectivity, MultipleDriversOnOneNet) {
  Netlist nl;
  const NetId a = nl.AddInput("a");
  const NetId b = nl.AddInput("b");
  const NetId bus = nl.AddWire("bus");

  const GateId g1 = nl.AddGate(GateType::kBuf, { a }, bus);
  const GateId g2 = nl.AddGate(GateType::kBuf, { b }, bus);

  EXPECT_EQ(nl.GetNet(bus).drivers, (std::vector<GateId>{ g1, g2 }));
}

/* ==================================================
 * D flip-flop
 * ================================================== */

/**
 * @brief   Verify AddDff follows the D/CLK input and Q output pin convention
 */
TEST(NetlistDff, PinConvention) {
  Netlist nl;
  const NetId d = nl.AddInput("d");
  const NetId clk = nl.AddInput("clk");
  const NetId q = nl.AddOutput("q");
  const GateId dff = nl.AddDff(d, clk, q);

  const Netlist::Gate& gate = nl.GetGate(dff);

  EXPECT_EQ(gate.type, GateType::kDff);
  EXPECT_TRUE(IsSequential(gate.type));

  ASSERT_EQ(gate.inputs.size(), 2u);
  EXPECT_EQ(gate.inputs[0], d);
  EXPECT_EQ(gate.inputs[1], clk);
  EXPECT_EQ(gate.output, q);
}

/**
 * @brief   Verify a D flip-flop wires its D/CLK fanout and Q drivers
 */
TEST(NetlistDff, Connectivity) {
  Netlist nl;
  const NetId d = nl.AddInput("d");
  const NetId clk = nl.AddInput("clk");
  const NetId q = nl.AddOutput("q");
  const GateId dff = nl.AddDff(d, clk, q);

  EXPECT_EQ(nl.GetNet(d).fanout, (std::vector<GateId>{ dff }));
  EXPECT_EQ(nl.GetNet(clk).fanout, (std::vector<GateId>{ dff }));
  EXPECT_EQ(nl.GetNet(q).drivers, (std::vector<GateId>{ dff }));
}

/**
 * @brief   Verify a D flip-flop follows a custom propagation delay
 */
TEST(NetlistDff, CustomDelay) {
  Netlist nl;
  const NetId d = nl.AddInput("d");
  const NetId clk = nl.AddInput("clk");
  const NetId q = nl.AddOutput("q");
  const GateId dff = nl.AddDff(d, clk, q, 3);

  EXPECT_EQ(nl.GetGate(dff).delay, Time{ 3 });
}

/* ==================================================
 * Full-adder fixture
 * ================================================== */

struct FullAdder {
  Netlist nl;
  NetId a;
  NetId b;
  NetId cin;
  NetId sum;
  NetId cout;
};

/**
 * @brief   Create a full-adder from the design's Verilog example
 * @return  A FullAdder holding the netlist and its boundary net handles
 */
static FullAdder MakeFullAdder() {
  FullAdder fa;

  fa.a = fa.nl.AddInput("a");
  fa.b = fa.nl.AddInput("b");
  fa.cin = fa.nl.AddInput("cin");
  fa.sum = fa.nl.AddOutput("sum");
  fa.cout = fa.nl.AddOutput("cout");

  const NetId w1 = fa.nl.AddWire("w1");
  const NetId w2 = fa.nl.AddWire("w2");
  const NetId w3 = fa.nl.AddWire("w3");

  fa.nl.AddGate(GateType::kXor, { fa.a, fa.b }, w1);
  fa.nl.AddGate(GateType::kXor, { w1, fa.cin }, fa.sum);
  fa.nl.AddGate(GateType::kAnd, { fa.a, fa.b }, w2);
  fa.nl.AddGate(GateType::kAnd, { w1, fa.cin }, w3);
  fa.nl.AddGate(GateType::kOr, { w2, w3 }, fa.cout);

  return fa;
}

/**
 * @brief   Verify the full-adder fixture has the expected net and gate counts
 */
TEST(NetlistFullAdder, Structure) {
  const FullAdder fa = MakeFullAdder();

  EXPECT_EQ(fa.nl.NumNets(), 8u);
  EXPECT_EQ(fa.nl.NumGates(), 5u);
  EXPECT_EQ(fa.nl.PrimaryInputs().size(), 3u);
  EXPECT_EQ(fa.nl.PrimaryOutputs().size(), 2u);
}

/**
 * @brief   Verify the full-adder's primary inputs and outputs are wired at the boundary
 */
TEST(NetlistFullAdder, Boundary) {
  const FullAdder fa = MakeFullAdder();

  EXPECT_TRUE(fa.nl.GetNet(fa.a).drivers.empty());
  EXPECT_FALSE(fa.nl.GetNet(fa.a).fanout.empty());

  EXPECT_EQ(fa.nl.GetNet(fa.sum).drivers.size(), 1u);
  EXPECT_EQ(fa.nl.GetNet(fa.cout).drivers.size(), 1u);
}

/**
 * @brief   Verify the full-adder's shared inputs each fan out to two gates
 */
TEST(NetlistFullAdder, InternalFanout) {
  const FullAdder fa = MakeFullAdder();

  EXPECT_EQ(fa.nl.GetNet(fa.a).fanout.size(), 2u);
  EXPECT_EQ(fa.nl.GetNet(fa.b).fanout.size(), 2u);
}