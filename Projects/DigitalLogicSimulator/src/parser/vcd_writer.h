/**
 * @file    vcd_writer.h
 * @brief   Value Change Dump (VCD) waveform writer
 * @author  Astatine387
 */

#pragma once

#include <cstddef>
#include <iosfwd>
#include <string>
#include <string_view>
#include <vector>

#include "core/logic4.h"
#include "core/netlist.h"

inline constexpr std::string_view kDefaultModuleName = "top";  // Default module name emitted in $scope

inline constexpr std::string_view kDefaultTimescale = "1ns";  // Default time unit emitted in $timescale

inline constexpr char kFirstIdCode = '!';  // First printable ASCII character used in a VCD identifier code

inline constexpr char kLastIdCode = '~';  // Last printable ASCII character used in a VCD identifier code

inline constexpr std::size_t kIdCodeRadix = static_cast<std::size_t>(kLastIdCode - kFirstIdCode) + 1;  // Radix 94

/**
 * @class   VcdWriter
 * @brief   Streams a netlist's 4-state value changes as a VCD waveform
 */
class VcdWriter {
 public:
  /**
   * @brief     Construct a writer bound to a netlist and an output stream
   * @param     netlist     Netlist whose nets are dumped
   * @param     out         Output stream for the VCD text
   * @param     module      Module name emitted in $scope
   * @param     timescale   Time unit emitted in $timescale
   */
  VcdWriter(const Netlist& netlist, std::ostream& out, std::string_view module = kDefaultModuleName,
            std::string_view timescale = kDefaultTimescale);

  VcdWriter(const VcdWriter&) = delete;
  VcdWriter& operator=(const VcdWriter&) = delete;

  /**
   * @brief   Emit the header, then the initial all-X dump at time 0
   */
  void WriteHeader();

  /**
   * @brief     Record one net value change
   * @param     time    Simulation time of the change
   * @param     net     Net whose value changed
   * @param     value   New resolved value of the net
   */
  void OnValueChange(Time time, NetId net, Logic4 value);

  /**
   * @brief     Emit a closing time marker
   * @param     end_time    Simulation time at which the run stopped
   */
  void Finish(Time end_time);

  /**
   * @brief     Read the VCD identifier code assigned to a net
   * @param     net     Net to look up
   * @return    Identifier code of the net
   */
  [[nodiscard]] std::string_view Code(NetId net) const { return codes_[Index(net)]; }

  /**
   * @brief     Read the dumped signal name of a net
   * @param     net     Net to look up
   * @return    Declared name of the net, or its synthesized name if it is anonymous
   */
  [[nodiscard]] std::string_view Name(NetId net) const { return names_[Index(net)]; }

 private:
  /**
   * @brief     Build the printable identifier code for a net index
   * @param     idx     Net storage index
   * @return    Identifier code, base-94 over the printable ASCII range
   */
  [[nodiscard]] static std::string MakeCode(std::size_t idx);

  /**
   * @brief     Emit a #time marker if the timeline has advanced
   * @param     time    Simulation time about to be dumped
   */
  void EmitTimeMarker(Time time);

  const Netlist& netlist_;          // netlist being dumped
  std::ostream& out_;               // VCD text sink
  std::string module_;              // module name for $scope
  std::string timescale_;           // time unit for $timescale
  std::vector<std::string> codes_;  // identifier code per NetId
  std::vector<std::string> names_;  // dumped signal name per NetId
  Time last_time_ = 0;              // simulation time of the last emitted marker
  bool header_written_ = false;     // whether the header and initial dump were emitted
};