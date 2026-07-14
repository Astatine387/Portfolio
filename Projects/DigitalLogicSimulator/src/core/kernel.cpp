/**
 * @file    kernel.cpp
 * @brief   Out-of-line definitions for event-driven, 4-state simulation kernel
 * @author  Astatine387
 */

#include "core/kernel.h"

#include <algorithm>
#include <cassert>
#include <cstddef>
#include <numeric>
#include <vector>

void Kernel::Poke(NetId net, Logic4 value, Time at) {
  assert(netlist_.GetNet(net).drivers.empty() && "Poke expects a driverless primary input");

  Schedule(net, value, at);
}

RunResult Kernel::Run(Time until) {
  RunResult res;

  while (!queue_.empty()) {
    const Time t = queue_.top().time;

    if (t > until) {
      break;
    }

    now_ = t;

    std::size_t delta = 0;

    while (!queue_.empty() && queue_.top().time == t) {
      if (++delta > max_cycles_) {
        res.status = RunStatus::kOscillation;
        res.end_time = t;

        std::vector<NetId>& nets = res.unstable_nets;

        while (!queue_.empty() && queue_.top().time == t) {
          nets.push_back(queue_.top().net);
          queue_.pop();
        }

        std::sort(nets.begin(), nets.end(), [](NetId a, NetId b) { return Index(a) < Index(b); });

        nets.erase(std::unique(nets.begin(), nets.end()), nets.end());

        return res;
      }

      std::vector<Event> batch;

      while (!queue_.empty() && queue_.top().time == t) {
        batch.push_back(queue_.top());
        queue_.pop();
      }

      std::vector<GateId> to_eval;

      for (std::size_t i = 0; i < batch.size(); i++) {
        if (i + 1 < batch.size() && batch[i + 1].net == batch[i].net) {
          continue;
        }

        const Logic4 value = batch[i].value;
        const NetId net = batch[i].net;

        if (value == net_values_[Index(net)]) {
          continue;
        }

        net_values_[Index(net)] = value;
        res.value_changes++;

        if (vcb_) {
          vcb_(t, net, value);
        }

        const Netlist::Net& sink = netlist_.GetNet(net);

        to_eval.insert(to_eval.end(), sink.fanout.begin(), sink.fanout.end());
      }

      std::sort(to_eval.begin(), to_eval.end(), [](GateId a, GateId b) { return Index(a) < Index(b); });

      to_eval.erase(std::unique(to_eval.begin(), to_eval.end()), to_eval.end());

      for (const GateId gate : to_eval) {
        EvaluateGate(gate, t);
      }
    }
  }

  if (queue_.empty()) {
    res.status = RunStatus::kQuiescent;
    res.end_time = now_;
  }
  else {
    res.status = RunStatus::kTimeLimit;
    res.end_time = until;
    now_ = until;
  }

  return res;
}

Logic4 Kernel::ResolveNet(NetId net) const {
  const Netlist::Net& record = netlist_.GetNet(net);

  if (record.drivers.empty()) {
    return net_values_[Index(net)];
  }

  return std::accumulate(record.drivers.begin(), record.drivers.end(), Logic4::kZ,
                         [this](Logic4 acc, GateId driver) { return Resolve(acc, driver_values_[Index(driver)]); });
}

void Kernel::EvaluateGate(GateId gate_id, Time now) {
  const Netlist::Gate& gate = netlist_.GetGate(gate_id);
  const std::size_t index = Index(gate_id);

  Logic4 output = Logic4::kX;

  if (IsSequential(gate.type)) {
    const Logic4 clock = net_values_[Index(gate.inputs[1])];
    const Logic4 prev = prev_clocks_[index];

    prev_clocks_[index] = clock;

    const bool rising = prev == Logic4::k0 && clock == Logic4::k1;

    output = rising ? net_values_[Index(gate.inputs[0])] : driver_values_[index];
  }
  else {
    const auto reduce = [&](Logic4 (*op)(Logic4, Logic4), Logic4 identity) {
      Logic4 acc = identity;

      for (const NetId in : gate.inputs) {
        acc = op(acc, net_values_[Index(in)]);
      }

      return acc;
    };

    switch (gate.type) {
      case GateType::kAnd:
        output = reduce(And, Logic4::k1);
        break;
      case GateType::kOr:
        output = reduce(Or, Logic4::k0);
        break;
      case GateType::kXor:
        output = reduce(Xor, Logic4::k0);
        break;
      case GateType::kNand:
        output = Not(reduce(And, Logic4::k1));
        break;
      case GateType::kNor:
        output = Not(reduce(Or, Logic4::k0));
        break;
      case GateType::kXnor:
        output = Not(reduce(Xor, Logic4::k0));
        break;
      case GateType::kNot:
        output = Not(net_values_[Index(gate.inputs[0])]);
        break;
      case GateType::kBuf:
        output = Buf(net_values_[Index(gate.inputs[0])]);
        break;
      case GateType::kDff:
        break;
    }
  }

  if (output == driver_values_[index]) {
    return;
  }

  driver_values_[index] = output;
  Schedule(gate.output, ResolveNet(gate.output), now + gate.delay);
}

void Kernel::Schedule(NetId net, Logic4 val, Time when) {
  queue_.push(Event{ when, next_seq_++, net, val });
}