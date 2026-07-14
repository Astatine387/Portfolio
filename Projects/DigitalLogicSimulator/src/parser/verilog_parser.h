/**
 * @file    verilog_parser.h
 * @brief   Structural, gate-level verilog subset parser
 * @author  Astatine387
 */

#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>

#include "core/netlist.h"

/**
 * @enum class	ParseStatus
 * @brief		Why a parse attempt stopped
 */
enum class ParseStatus : std::uint8_t {
  kOk,                    // Parsed successfully
  kSyntaxError,           // Unexpected or missing token
  kUnsupportedConstruct,  // Valid Verilog outside the structural subset
  kUndeclaredNet,         // A port or gate references an undeclared net
  kDuplicateDeclaration,  // A net name declared more than once
};

/**
 * @struct	ParseError
 * @brief	Location and description of the first failure
 */
struct ParseError {
  std::size_t line = 0;  // 1-based line of the offending token
  std::size_t col = 0;   // 1-based column of the offending token
  std::string msg;       // Detail, names the offending construct
};

/**
 * @struct	ParseResult
 * @brief	Outcome of a parse: the netlist on success, else the error
 */
struct ParseResult {
  ParseStatus status = ParseStatus::kOk;  // Why parsing stopped
  Netlist netlist;                        // Constructed IR; empty unless status == kOk
  ParseError err;                         // Valid unless status == kOk

  [[nodiscard]] bool Ok() const { return status == ParseStatus::kOk; }
};

/**
 * @brief	Parse structural Verilog into a Netlist
 * @param	source	Verilog string to parse
 * @return	Outcome of a parse: the netlist on success, else the error
 */
[[nodiscard]] ParseResult ParseVerilog(std::string_view src);