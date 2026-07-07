/**
 * @file    kernel.h
 * @brief   Event-driven, 4-state simulation kernel
 * @author  Astatine387
 */

#pragma once

#include <cstddef>
#include <cstdint>
#include <functional>
#include <limits>
#include <queue>
#include <utility>
#include <vector>

#include "core/logic4.h"
#include "core/netlist.h"

inline constexpr Time kNoTimeLimit = std::numeric_limits<Time>::max();  // Sentinel for Kernel

inline constexpr std::size_t kDefaultMaxDeltaCycles = 10000;  // Default cap on delta cycles per time step

/**
 * @enum    RunStatus
 * @brief   Reason a Kernel::Run call stopped
 */
enum class RunStatus : std::uint8_t {
  kQuiescent,    // Event queue drained
  kTimeLimit,    // Reached the requested time limit
  kOscillation,  // Delta-cycle cap exceeded
};

/**
 * @struct  RunResult
 * @brief   Outcome and statistics of a Kernel::Run call
 */
struct RunResult {
  RunStatus status = RunStatus::kQuiescent;  // Why the run stopped
  Time end_time = 0;                         // Simulation time when the run stopped
  std::uint64_t value_changes = 0;           // Net value changes committed during the run
  std::vector<NetId> unstable_nets;          // Nets left toggling when kOscillation is reported
};

/**
 * @class   Kernel
 * @brief   Event-driven, 4-state simulation kernel over a flat Netlist
 */
class Kernel {
 public:
  /**
   * @brief     Callback invoked on every committed net value change
   * @param     time    Simulation time of the change
   * @param     net     Net whose value changed
   * @param     value   New resolved value of the net
   */
  using ValueChangeCallback = std::function<void(Time time, NetId net, Logic4 value)>;

  /**
   * @brief     Construct a kernel
   * @param     netlist     Netlist to simulate
   */
  explicit Kernel(const Netlist& netlist)
      : netlist_(netlist),
        net_values_(netlist.NumNets(), Logic4::kX),
        driver_values_(netlist.NumGates(), Logic4::kX),
        prev_clocks_(netlist.NumGates(), Logic4::kX) {}

  /**
   * @brief     Schedule a stimulus value on a primary input net
   * @param     net     Primary input net to drive
   * @param     value   Value the net takes
   * @param     at      Simulation time at which the value is applied
   */
  void Poke(NetId net, Logic4 value, Time at);

  /**
   * @brief   Run the event loop until quiescence or a time limit
   * @param   until     Events beyond it stay queued for a later call
   * @return  Outcome and statistics of the run
   */
  RunResult Run(Time until = kNoTimeLimit);

  /**
   * @brief     Read the current value of a net
   * @param     net     Net to read
   * @return    Current resolved value of the net
   */
  [[nodiscard]] Logic4 Value(NetId net) const { return net_values_[Index(net)]; }

  /**
   * @brief     Get the current simulation time
   * @return    Simulation time reached so far
   */
  [[nodiscard]] Time Now() const { return now_; }

  /**
   * @brief     Set value change callback function
   * @param     vcb     Value change callback
   */
  void SetValueChangeCallback(ValueChangeCallback vcb) { vcb_ = std::move(vcb); }

  /**
   * @brief     Set maximum delta cycles before oscillation is reported
   * @param     limit   Maximum delta cycles
   */
  void SetMaxDeltaCycles(std::size_t limit) { max_cycles_ = limit; }

 private:
  /**
   * @struct    Event
   * @brief     A pending change of a net to a value at a time
   */
  struct Event {
    Time time;          // time at which the change takes effect
    std::uint64_t seq;  // insertion order
    NetId net;          // affected net
    Logic4 value;       // value the net takes
  };

  /**
   * @struct    EventLater
   * @brief     Orders events for a min-time priority queue with stable ties
   */
  struct EventLater {
    bool operator()(const Event& a, const Event& b) const {
      if (a.time != b.time) {
        return a.time > b.time;
      }

      if (a.net != b.net) {
        return Index(a.net) > Index(b.net);
      }

      return a.seq > b.seq;
    }
  };

  /**
   * @brief     Resolve a net from all of its drivers' last-driven values
   * @param     net     Net to resolve
   * @return    Resolved value of the net
   */
  [[nodiscard]] Logic4 ResolveNet(NetId net) const;

  /**
   * @brief     Evaluate one gate and schedule its output net change
   * @param     gate    Gate to evaluate
   * @param     now     Current simulation time
   */
  void EvaluateGate(GateId gate, Time now);

  /**
   * @brief     Enqueue a net value change
   * @param     net     Net to change
   * @param     value   Value the net takes
   * @param     when    Time at which the change takes effect
   */
  void Schedule(NetId net, Logic4 value, Time when);

  const Netlist& netlist_;                                            // netlist under simulation
  std::vector<Logic4> net_values_;                                    // current value per net, by NetId
  std::vector<Logic4> driver_values_;                                 // last value each gate drives
  std::vector<Logic4> prev_clocks_;                                   // last clock seen per gate
  std::priority_queue<Event, std::vector<Event>, EventLater> queue_;  // pending events
  std::uint64_t next_seq_ = 0;                                        // next event sequence number
  Time now_ = 0;                                                      // current simulation time
  std::size_t max_cycles_ = kDefaultMaxDeltaCycles;                   // oscillation guard
  ValueChangeCallback vcb_;                                           // change sink (e.g. a VCD writer)
};