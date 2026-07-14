/**
 * @file    vcd_writer.cpp
 * @brief   Out-of-line definitions for VCD waveform writer
 * @author  Astatine387
 */

#include "parser/vcd_writer.h"

#include <cstddef>
#include <ostream>
#include <string>

#include "core/logic4.h"
#include "core/netlist.h"

VcdWriter::VcdWriter(const Netlist& netlist, std::ostream& out, std::string_view module, std::string_view timescale)
    : netlist_(netlist),
      out_(out),
      module_(module),
      timescale_(timescale),
      codes_(netlist.NumNets()),
      names_(netlist.NumNets()) {
  for (std::size_t i = 0; i < netlist_.NumNets(); i++) {
    const Netlist::Net& net = netlist_.GetNet(MakeNetId(i));

    codes_[i] = MakeCode(i);
    names_[i] = net.name.empty() ? "_n" + std::to_string(i) : net.name;
  }
}

void VcdWriter::WriteHeader() {
  if (header_written_) {
    return;
  }

  header_written_ = true;

  out_ << "$version DigitalLogicSimulator $end\n";
  out_ << "$timescale " << timescale_ << " $end\n";
  out_ << "$scope module " << module_ << " $end\n";

  for (std::size_t i = 0; i < netlist_.NumNets(); i++) {
    out_ << "$var wire 1 " << codes_[i] << ' ' << names_[i] << " $end\n";
  }

  out_ << "$upscope $end\n";
  out_ << "$enddefinitions $end\n";

  out_ << "#0\n";
  out_ << "$dumpvars\n";

  for (std::size_t i = 0; i < netlist_.NumNets(); i++) {
    out_ << ToChar(Logic4::kX) << codes_[i] << '\n';
  }

  out_ << "$end\n";

  last_time_ = 0;
}

void VcdWriter::OnValueChange(Time time, NetId net, Logic4 value) {
  if (!header_written_) {
    WriteHeader();
  }

  EmitTimeMarker(time);

  out_ << ToChar(value) << codes_[Index(net)] << '\n';
}

void VcdWriter::Finish(Time end_time) {
  if (!header_written_) {
    WriteHeader();
  }

  EmitTimeMarker(end_time);
}

std::string VcdWriter::MakeCode(std::size_t idx) {
  std::string code;

  do {
    const std::size_t digit = idx % kIdCodeRadix;

    code.push_back(static_cast<char>(kFirstIdCode + digit));
    idx /= kIdCodeRadix;
  } while (idx > 0);

  return code;
}

void VcdWriter::EmitTimeMarker(Time time) {
  if (time > last_time_) {
    out_ << '#' << time << '\n';
    last_time_ = time;
  }
}