/**
 * @file    verilog_parser.cpp
 * @brief   Out-of-line definitions for structural, gate-level verilog subset parser
 * @author  Astatine387
 */

#include "parser/verilog_parser.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

#include "core/netlist.h"

namespace {

/* ==================================================
 * Tokens
 * ================================================== */

/**
 * @enum    TokenKind
 * @brief   Lexical category of a token
 */
enum class TokenKind : std::uint8_t {
  kWord,       // identifier or keyword
  kLParen,     // (
  kRParen,     // )
  kComma,      // ,
  kSemicolon,  // ;
  kLBracket,   // [
  kEof,        // end of input
};

/**
 * @struct  Token
 * @brief   One lexical token with its source position
 */
struct Token {
  TokenKind kind = TokenKind::kEof;  // lexical category
  std::string_view text;             // spelling, populated for kWord
  std::size_t line = 1;              // 1-based line
  std::size_t col = 1;               // 1-based column
};

/* ==================================================
 * Character classes (ASCII, locale-independent)
 * ================================================== */

/**
 * @brief   Check whether a character is inter-token whitespace
 * @param   c   Character to test
 * @return  Whether a character is inter-token whitespace
 */
[[nodiscard]] constexpr bool IsSpace(char c) {
  return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f' || c == '\v';
}

/**
 * @brief   Check whether a character may start an identifier
 * @param   c   Character to test
 * @return  Whether a character may start an identifier
 */
[[nodiscard]] constexpr bool IsIdentStart(char c) {
  return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_';
}

/**
 * @brief   Check whether a character may continue an identifier
 * @param   c   Character to test
 * @return  Whether a character may continue an identifier
 */
[[nodiscard]] constexpr bool IsIdentCont(char c) {
  return IsIdentStart(c) || (c >= '0' && c <= '9') || c == '$';
}

/* ==================================================
 * Keyword tables
 * ================================================== */

/**
 * @brief     Map a primitive-gate keyword to its GateType
 * @param     word    Keyword
 * @return    Gate type if the word is a supported primitive, else nullopt
 */
[[nodiscard]] std::optional<GateType> GateTypeOf(std::string_view word) {
  if (word == "and") {
    return GateType::kAnd;
  }

  if (word == "or") {
    return GateType::kOr;
  }

  if (word == "not") {
    return GateType::kNot;
  }

  if (word == "nand") {
    return GateType::kNand;
  }

  if (word == "nor") {
    return GateType::kNor;
  }

  if (word == "xor") {
    return GateType::kXor;
  }

  if (word == "xnor") {
    return GateType::kXnor;
  }

  if (word == "buf") {
    return GateType::kBuf;
  }

  return std::nullopt;
}

/**
 * @brief     Generate human-readable spelling of a gate type
 * @param     type    Gate type
 * @return    Human-readable spelling of a gate type
 */
[[nodiscard]] std::string_view GateName(GateType type) {
  switch (type) {
    case GateType::kAnd:
      return "and";
    case GateType::kOr:
      return "or";
    case GateType::kNot:
      return "not";
    case GateType::kNand:
      return "nand";
    case GateType::kNor:
      return "nor";
    case GateType::kXor:
      return "xor";
    case GateType::kXnor:
      return "xnor";
    case GateType::kBuf:
      return "buf";
    case GateType::kDff:
      return "dff";
  }
  return "gate";
}

/**
 * @brief     Whether a word names a construct outside the structural subset
 * @param     word    Candidate keyword
 * @return    True for known behavioral but unsupported Verilog keywords
 */
[[nodiscard]] bool IsUnsupportedKeyword(std::string_view word) {
  static constexpr auto kKeywords = std::to_array<std::string_view>({
      "always",   "initial", "reg",       "assign",  "parameter", "localparam", "generate", "genvar",
      "function", "task",    "primitive", "specify", "integer",   "real",       "time",     "event",
      "force",    "release", "fork",      "join",    "case",      "casex",      "casez",    "defparam",
      "tri",      "wand",    "wor",       "supply0", "supply1",   "posedge",    "negedge",  "if",
      "else",     "for",     "while",     "repeat",  "forever",
  });

  for (const std::string_view keyword : kKeywords) {
    if (word == keyword) {
      return true;
    }
  }

  return false;
}

/**
 * @brief     Convert a token into a string to be included in an error message
 * @param     tok     Token to be converted
 * @return    Quoted spelling for words and punctuation, or a phrase for EOF
 */
[[nodiscard]] std::string Describe(const Token& tok) {
  switch (tok.kind) {
    case TokenKind::kWord:
      return "'" + std::string(tok.text) + "'";
    case TokenKind::kLParen:
      return "'('";
    case TokenKind::kRParen:
      return "')'";
    case TokenKind::kComma:
      return "','";
    case TokenKind::kSemicolon:
      return "';'";
    case TokenKind::kLBracket:
      return "'['";
    case TokenKind::kEof:
      return "end of input";
  }
  return "token";
}

/* ==================================================
 * Parser
 * ================================================== */

/**
 * @class   Parser
 * @brief   Lexes on demand and builds a Netlist
 */
class Parser {
 public:
  explicit Parser(std::string_view source) : src_(source) {}

  /**
   * @brief   Parse the source
   * @return  The netlist on success, otherwise the first error
   */
  ParseResult Run() {
    ParseModule();

    if (ok_) {
      ExpectEof();
    }

    ParseResult res;

    res.status = status_;
    res.err = err_;

    if (ok_) {
      res.netlist = std::move(netlist_);
    }

    return res;
  }

 private:
  /**
   * @brief     Record the first parse failure and stop making progress
   * @param     status  Failure category
   * @param     at      Token whose position locates the failure
   * @param     msg     Human-readable detail
   */
  void Fail(ParseStatus status, const Token& at, std::string msg) {
    if (!ok_) {
      return;  // keep the first error
    }

    ok_ = false;
    status_ = status;
    err_.line = at.line;
    err_.col = at.col;
    err_.msg = std::move(msg);
  }

  /**
   * @brief   Look at the next token
   * @return  Reference to the buffered lookahead token
   */
  const Token& Peek() {
    if (!look_) {
      look_ = Lex();
    }

    return *look_;
  }

  /**
   * @brief   Consume and return the next token
   * @return  The consumed token
   */
  Token Consume() {
    const Token tok = Peek();

    look_.reset();

    return tok;
  }

  /**
   * @brief   Advance one raw character
   */
  void AdvanceChar() {
    if (src_[pos_] == '\n') {
      line_++;
      col_ = 1;
    }
    else {
      col_++;
    }

    pos_++;
  }

  /**
   * @brief   Skip whitespace and comments
   */
  void SkipTrivia() {
    while (pos_ < src_.size()) {
      const char c = src_[pos_];

      /* Skip whitespace */

      if (IsSpace(c)) {
        AdvanceChar();
        continue;
      }

      /* Skip line comment */

      if (c == '/' && pos_ + 1 < src_.size() && src_[pos_ + 1] == '/') {
        AdvanceChar();
        AdvanceChar();

        while (pos_ < src_.size() && src_[pos_] != '\n') {
          AdvanceChar();
        }

        continue;
      }

      /* Skip block comment */

      if (c == '/' && pos_ + 1 < src_.size() && src_[pos_ + 1] == '*') {
        Token open;

        open.line = line_;
        open.col = col_;
        AdvanceChar();
        AdvanceChar();

        bool closed = false;

        while (pos_ < src_.size()) {
          if (src_[pos_] == '*' && pos_ + 1 < src_.size() && src_[pos_ + 1] == '/') {
            AdvanceChar();
            AdvanceChar();
            closed = true;

            break;
          }

          AdvanceChar();
        }

        if (!closed) {
          Fail(ParseStatus::kSyntaxError, open, "unterminated block comment");
          pos_ = src_.size();
        }

        continue;
      }

      break;
    }
  }

  /**
   * @brief   Produce the next token from the source
   * @return  The lexed token, or an EOF token once input (or a lex error) ends
   */
  Token Lex() {
    SkipTrivia();

    Token tok;

    tok.line = line_;
    tok.col = col_;

    if (pos_ >= src_.size()) {
      tok.kind = TokenKind::kEof;
      return tok;
    }

    const char c = src_[pos_];

    if (IsIdentStart(c)) {
      const std::size_t start = pos_;

      while (pos_ < src_.size() && IsIdentCont(src_[pos_])) {
        AdvanceChar();
      }

      tok.kind = TokenKind::kWord;
      tok.text = src_.substr(start, pos_ - start);

      return tok;
    }

    switch (c) {
      case '(':
        AdvanceChar();
        tok.kind = TokenKind::kLParen;
        return tok;
      case ')':
        AdvanceChar();
        tok.kind = TokenKind::kRParen;
        return tok;
      case ',':
        AdvanceChar();
        tok.kind = TokenKind::kComma;
        return tok;
      case ';':
        AdvanceChar();
        tok.kind = TokenKind::kSemicolon;
        return tok;
      case '[':
        AdvanceChar();
        tok.kind = TokenKind::kLBracket;
        return tok;
      default:
        break;
    }

    /* Report and end the stream meeting an unexpected character */

    std::string mes = "unexpected character '";

    mes += c;
    mes += "'";

    Fail(ParseStatus::kSyntaxError, tok, std::move(mes));

    pos_ = src_.size();
    tok.kind = TokenKind::kEof;

    return tok;
  }

  /**
   * @brief     Whether the next token has the given kind
   * @param     kind    Kind to test for
   */
  [[nodiscard]] bool Check(TokenKind kind) { return Peek().kind == kind; }

  /**
   * @brief     Consume the next token if it has the given kind
   * @param     kind    Kind to accept
   * @return    True if a token was consumed
   */
  bool Accept(TokenKind kind) {
    if (Check(kind)) {
      Consume();
      return true;
    }

    return false;
  }

  /**
   * @brief     Consume a token of the given kind or record a syntax error
   * @param     kind    Required kind
   * @param     msg     Description of the expected token, for the message
   * @return    The consumed token on success, else the offending token
   */
  Token Expect(TokenKind kind, std::string_view msg) {
    if (Check(kind)) {
      return Consume();
    }

    const Token& tok = Peek();

    Fail(ParseStatus::kSyntaxError, tok, "expected " + std::string(msg) + ", found " + Describe(tok));

    return tok;
  }

  /**
   * @brief     Consume a specific keyword or record a syntax error
   * @param     word    Word that must appear next
   * @param     msg     Description of the expected keyword, for the message
   * @return    True if the keyword was consumed
   */
  bool ExpectKeyword(std::string_view word, std::string_view msg) {
    const Token& tok = Peek();

    if (tok.kind == TokenKind::kWord && tok.text == word) {
      Consume();
      return true;
    }

    Fail(ParseStatus::kSyntaxError, tok, "expected " + std::string(msg) + ", found " + Describe(tok));

    return false;
  }

  /**
   * @brief     Declare a net, creating it in the netlist
   * @param     kind    Boundary role of the net
   * @param     name    Identifier token naming the net
   */
  void DeclareNet(NetKind kind, const Token& name) {
    if (!ok_) {
      return;
    }

    if (symbols_.contains(name.text)) {
      Fail(ParseStatus::kDuplicateDeclaration, name, "net '" + std::string(name.text) + "' is declared more than once");
      return;
    }

    NetId id{};

    switch (kind) {
      case NetKind::kInput:
        id = netlist_.AddInput(name.text);
        break;
      case NetKind::kOutput:
        id = netlist_.AddOutput(name.text);
        break;
      case NetKind::kWire:
        id = netlist_.AddWire(name.text);
        break;
    }

    symbols_.emplace(name.text, id);
  }

  /**
   * @brief     Resolve a net reference to its handle
   * @param     name    Identifier token naming the net
   * @return    Handle of the net, or a default handle if it is undeclared
   */
  NetId LookupNet(const Token& name) {
    const auto it = symbols_.find(name.text);

    if (it == symbols_.end()) {
      Fail(ParseStatus::kUndeclaredNet, name, "net '" + std::string(name.text) + "' is not declared");
      return NetId{};
    }

    return it->second;
  }

  /**
   * @brief   module IDENT ( ports ) ; items endmodule
   */
  void ParseModule() {
    if (!ExpectKeyword("module", "'module'")) {
      return;
    }

    Expect(TokenKind::kWord, "module name");  // name is not stored in the IR

    if (!ok_) {
      return;
    }

    ParsePortList();

    if (!ok_) {
      return;
    }

    Expect(TokenKind::kSemicolon, "';'");

    if (!ok_) {
      return;
    }

    ParseItems();
  }

  /**
   * @brief   ( ) | ( IDENT ( , IDENT )* )
   */
  void ParsePortList() {
    Expect(TokenKind::kLParen, "'('");

    if (!ok_) {
      return;
    }

    if (Accept(TokenKind::kRParen)) {
      return;  // Empty port list
    }

    for (;;) {
      if (!ok_) {
        return;
      }

      if (Check(TokenKind::kLBracket)) {
        Fail(ParseStatus::kUnsupportedConstruct, Peek(), "vector ports are not supported (scalar only)");
        return;
      }

      Expect(TokenKind::kWord, "port name");

      if (!ok_) {
        return;
      }

      if (Accept(TokenKind::kComma)) {
        continue;
      }

      break;
    }

    Expect(TokenKind::kRParen, "')'");
  }

  /**
   * @brief   Module body: a run of declarations and gate instances up to endmodule
   */
  void ParseItems() {
    for (;;) {
      if (!ok_) {
        return;
      }

      const Token tok = Peek();

      if (tok.kind == TokenKind::kEof) {
        Fail(ParseStatus::kSyntaxError, tok, "expected 'endmodule', found end of input");
        return;
      }

      if (tok.kind == TokenKind::kWord) {
        if (tok.text == "endmodule") {
          Consume();
          return;
        }

        if (tok.text == "input") {
          Consume();
          ParseNetDecl(NetKind::kInput);
          continue;
        }

        if (tok.text == "output") {
          Consume();
          ParseNetDecl(NetKind::kOutput);
          continue;
        }

        if (tok.text == "wire") {
          Consume();
          ParseNetDecl(NetKind::kWire);
          continue;
        }

        if (const std::optional<GateType> gate = GateTypeOf(tok.text); gate) {
          const Token keyword = Consume();
          ParseGateInstance(*gate, keyword);
          continue;
        }

        if (IsUnsupportedKeyword(tok.text)) {
          Fail(ParseStatus::kUnsupportedConstruct, tok,
               "'" + std::string(tok.text) + "' is not supported (structural subset only)");
          return;
        }

        Fail(ParseStatus::kUnsupportedConstruct, tok,
             "unsupported construct '" + std::string(tok.text) +
                 "' (module instantiation / hierarchy is not supported)");
        return;
      }

      Fail(ParseStatus::kSyntaxError, tok, "expected a declaration or gate, found " + Describe(tok));

      return;
    }
  }

  /**
   * @brief     ( input | output | wire ) IDENT ( , IDENT )* ;
   * @param     kind    Boundary role to assign to each declared net
   */
  void ParseNetDecl(NetKind kind) {
    if (Check(TokenKind::kLBracket)) {
      Fail(ParseStatus::kUnsupportedConstruct, Peek(), "vector nets are not supported (scalar only)");
      return;
    }

    for (;;) {
      if (!ok_) {
        return;
      }

      const Token name = Expect(TokenKind::kWord, "net name");

      if (!ok_) {
        return;
      }

      DeclareNet(kind, name);

      if (Accept(TokenKind::kComma)) {
        continue;
      }

      break;
    }

    Expect(TokenKind::kSemicolon, "';'");
  }

  /**
   * @brief     gate_type [ IDENT ] ( output , inputs... ) ;
   * @param     type    Primitive gate type
   * @param     word    Gate keyword token, used to locate arity errors
   */
  void ParseGateInstance(GateType type, const Token& word) {
    if (Check(TokenKind::kWord)) {
      Consume();  // optional instance name, not stored
    }

    Expect(TokenKind::kLParen, "'('");

    if (!ok_) {
      return;
    }

    std::vector<NetId> ports;

    for (;;) {
      if (!ok_) {
        return;
      }

      const Token name = Expect(TokenKind::kWord, "net name");

      if (!ok_) {
        return;
      }

      ports.push_back(LookupNet(name));

      if (!ok_) {
        return;
      }

      if (Accept(TokenKind::kComma)) {
        continue;
      }

      break;
    }

    Expect(TokenKind::kRParen, "')'");

    if (!ok_) {
      return;
    }

    Expect(TokenKind::kSemicolon, "';'");

    if (!ok_) {
      return;
    }

    const std::size_t num_inputs = ports.size() - 1;  // ports has at least one output
    const bool single_input = (type == GateType::kNot || type == GateType::kBuf);

    if (single_input && num_inputs != 1) {
      Fail(ParseStatus::kSyntaxError, word, "'" + std::string(GateName(type)) + "' expects exactly one input");
      return;
    }

    if (!single_input && num_inputs < 1) {
      Fail(ParseStatus::kSyntaxError, word, "'" + std::string(GateName(type)) + "' expects at least one input");
      return;
    }

    const NetId output = ports.front();
    const std::span<const NetId> inputs(ports.data() + 1, num_inputs);
    netlist_.AddGate(type, inputs, output);
  }

  /**
   * @brief   Require that nothing but end-of-input follows the module
   */
  void ExpectEof() {
    const Token& tok = Peek();

    if (tok.kind == TokenKind::kEof) {
      return;
    }

    if (tok.kind == TokenKind::kWord && tok.text == "module") {
      Fail(ParseStatus::kUnsupportedConstruct, tok, "multiple modules are not supported");
    }
    else {
      Fail(ParseStatus::kSyntaxError, tok, "unexpected content after 'endmodule', found " + Describe(tok));
    }
  }

  Netlist netlist_;                                      // netlist under construction
  ParseStatus status_ = ParseStatus::kOk;                // failure category
  ParseError err_;                                       // first error, valid when !ok_
  std::unordered_map<std::string_view, NetId> symbols_;  // net name -> handle

  std::optional<Token> look_;  // one-token lookahead buffer
  std::string_view src_;       // whole source text
  std::size_t pos_ = 0;        // byte offset into src_
  std::size_t line_ = 1;       // current 1-based line
  std::size_t col_ = 1;        // current 1-based column
  bool ok_ = true;             // false once an error is recorded
};

}  // namespace

ParseResult ParseVerilog(std::string_view src) {
  Parser parser(src);
  return parser.Run();
}