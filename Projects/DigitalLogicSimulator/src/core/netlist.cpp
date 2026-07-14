/**
 * @file    netlist.cpp
 * @brief   Out-of-line definitions for netlist IR and builder
 * @author  Astatine387
 */

#include "core/netlist.h"

#include <cassert>
#include <span>
#include <string>
#include <vector>

NetId Netlist::AddInput(std::string_view name) {
  const NetId id = MakeNetId(nets_.size());

  nets_.push_back(Net{ NetKind::kInput, std::string(name), {}, {} });
  primary_inputs_.push_back(id);

  return id;
}

NetId Netlist::AddOutput(std::string_view name) {
  const NetId id = MakeNetId(nets_.size());

  nets_.push_back(Net{ NetKind::kOutput, std::string(name), {}, {} });
  primary_outputs_.push_back(id);

  return id;
}

NetId Netlist::AddWire(std::string_view name) {
  const NetId id = MakeNetId(nets_.size());

  nets_.push_back(Net{ NetKind::kWire, std::string(name), {}, {} });

  return id;
}

GateId Netlist::AddGate(GateType type, std::span<const NetId> inputs, NetId output, Time delay) {
  const GateId id = MakeGateId(gates_.size());

  gates_.push_back(Gate{
      .type = type,
      .inputs = std::vector<NetId>(inputs.begin(), inputs.end()),
      .output = output,
      .delay = delay,
  });

  for (const NetId in : inputs) {
    assert(Index(in) < nets_.size());
    nets_[Index(in)].fanout.push_back(id);
  }

  assert(Index(output) < nets_.size());
  nets_[Index(output)].drivers.push_back(id);

  return id;
}

GateId Netlist::AddGate(GateType type, std::initializer_list<NetId> inputs, NetId output, Time delay) {
  return AddGate(type, std::span<const NetId>(inputs.begin(), inputs.size()), output, delay);
}

GateId Netlist::AddDff(NetId data, NetId clock, NetId output, Time delay) {
  return AddGate(GateType::kDff, { data, clock }, output, delay);
}