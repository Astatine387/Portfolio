/**
 * @file    netlist.h
 * @brief   Netlist intermediate representation and builder
 * @author  Astatine387
 */

#pragma once

#include <cstddef>
#include <cstdint>
#include <initializer_list>
#include <span>
#include <string>
#include <string_view>
#include <vector>

/**
 * @brief   Simulation time unit, shared by event timestamps and gate delays
 */
using Time = std::uint64_t;

inline constexpr Time kDefaultDelay = 1;  // Default per-gate propagation delay

/**
 * @enum    NetId
 * @brief   Strong handle for a net
 */
enum class NetId : std::uint32_t {};

/**
 * @enum    GateId
 * @brief   Strong handle for a gate
 */
enum class GateId : std::uint32_t {};

/**
 * @enum    NetKind
 * @brief   Role of a net on the module boundary
 */
enum class NetKind : std::uint8_t {
  kInput,
  kOutput,
  kWire,
};

/**
 * @enum    GateType
 * @brief   Primitive cell type
 */
enum class GateType : std::uint8_t {
  kAnd,
  kOr,
  kNot,
  kNand,
  kNor,
  kXor,
  kXnor,
  kBuf,
  kDff,
};

/**
 * @brief   Convert a net handle to its storage index
 * @param   id  Net handle
 */
[[nodiscard]] constexpr std::size_t Index(NetId id) {
  return static_cast<std::size_t>(id);
}

/**
 * @brief   Convert a gate handle to its storage index.
 * @param   id  Gate handle
 */
[[nodiscard]] constexpr std::size_t Index(GateId id) {
  return static_cast<std::size_t>(id);
}

/**
 * @brief   Build a net handle from a storage index
 * @param   idx     Net index
 */
[[nodiscard]] constexpr NetId MakeNetId(std::size_t idx) {
  return static_cast<NetId>(idx);
}

/**
 * @brief   Build a gate handle from a storage index
 * @param   idx     Gate index
 */
[[nodiscard]] constexpr GateId MakeGateId(std::size_t idx) {
  return static_cast<GateId>(idx);
}

/**
 * @brief   Whether a gate type is a sequential element
 * @param   type    Gate type
 */
[[nodiscard]] constexpr bool IsSequential(GateType type) {
  return type == GateType::kDff;
}

/**
 * @class   Netlist
 * @brief   Flat, index-based netlist IR plus the builder used to construct it
 */
class Netlist {
 public:
  /**
   * @struct    Gate
   * @brief     One primitive cell
   */
  struct Gate {
    GateType type;               // primitive type
    std::vector<NetId> inputs;   // input nets
    NetId output;                // driven net
    Time delay = kDefaultDelay;  // propagation delay
  };

  /**
   * @struct  Net
   * @brief   One net (wire)
   */
  struct Net {
    NetKind kind = NetKind::kWire;  // boundary role
    std::string name;               // identifier, empty if anonymous
    std::vector<GateId> drivers;    // gates driving this net
    std::vector<GateId> fanout;     // gates to re-evaluate on change
  };

  /**
   * @brief     Add a primary input net driven externally by stimulus
   * @param     name    Gate name
   */
  NetId AddInput(std::string_view name);

  /**
   * @brief     Add a primary output net observed on the boundary
   * @param     name    Gate name
   */
  NetId AddOutput(std::string_view name);

  /**
   * @brief     Add an internal net
   * @param     name    Gate name
   */
  NetId AddWire(std::string_view name = {});

  /**
   * @brief     Add a gate and wire up its connectivity
   * @param     type    Gate type
   * @param     inputs  Input nets
   * @param     output  Output nets
   * @param     delay   Propagation delay in time units
   * @return    Handle of the new gate
   */
  GateId AddGate(GateType type, std::span<const NetId> inputs, NetId output, Time delay = kDefaultDelay);

  /**
   * @brief     Convenience overload taking a braced list of input nets
   * @param     type    Gate type
   * @param     inputs  Input nets
   * @param     output  Output nets
   * @param     delay   Propagation delay in time units
   * @return    Handle of the new gate
   */
  GateId AddGate(GateType type, std::initializer_list<NetId> inputs, NetId output, Time delay = kDefaultDelay);

  /**
   * @brief     Add a D flip-flop (D, CLK -> Q)
   * @param     data    Data input net
   * @param     clock   Clock input net
   * @param     output  Output net
   * @param     delay   Propagation delay in time units
   * @return    Handle of the new flip-flop
   */
  GateId AddDff(NetId data, NetId clock, NetId output, Time delay = kDefaultDelay);

  /**
   * @brief     Get the number of nets
   * @return    Number of nets in the netlist
   */
  [[nodiscard]] std::size_t NumNets() const { return nets_.size(); }

  /**
   * @brief     Get the number of gates
   * @return    Number of gates in the netlist
   */
  [[nodiscard]] std::size_t NumGates() const { return gates_.size(); }

  /**
   * @brief     Read a net by handle
   * @param     id  Net handle
   * @return    Reference to the net
   */
  [[nodiscard]] const Net& GetNet(NetId id) const { return nets_[Index(id)]; }

  /**
   * @brief     Read a gate by handle
   * @param     id  Gate handle
   * @return    Reference to the gate
   */
  [[nodiscard]] const Gate& GetGate(GateId id) const { return gates_[Index(id)]; }

  /**
   * @brief     Get a read-only view over all nets
   * @return    View over the net store
   */
  [[nodiscard]] std::span<const Net> Nets() const { return nets_; }

  /**
   * @brief     Get a read-only view over all gates, indexed by GateId
   * @return    View over the gate store
   */
  [[nodiscard]] std::span<const Gate> Gates() const { return gates_; }

  /**
   * @brief     Get the primary input nets in declaration order
   * @return    Handles of the primary input nets
   */
  [[nodiscard]] const std::vector<NetId>& PrimaryInputs() const { return primary_inputs_; }

  /**
   * @brief     Get the primary output nets in declaration order
   * @return    Handles of the primary output nets
   */
  [[nodiscard]] const std::vector<NetId>& PrimaryOutputs() const { return primary_outputs_; }

 private:
  std::vector<Net> nets_;               // All net records, indexed by NetId
  std::vector<Gate> gates_;             // All gate records, indexed by GateId
  std::vector<NetId> primary_inputs_;   // Handles of the primary input nets
  std::vector<NetId> primary_outputs_;  // Handles of the primary output nets
};