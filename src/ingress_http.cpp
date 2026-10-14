#include "egress.hpp"
#include "ingress.hpp"
#include <boost/capy/when_any.hpp>

#include <algorithm>
#include <array>
#include <charconv>
#include <set>

namespace zetta_tunnel::ingress {
namespace {

struct Completion {
  bool done = false;
  std::exception_ptr error;
};

capy::io_task<> complete(capy::task<> task, Completion &state) {
  std::exception_ptr error;
  try {
    co_await std::move(task);
  } catch (...) {
    error = std::current_exception();
  }
  if (!state.done) {
    state.done = true;
    state.error = error;
  }
  co_return {};
}

void require(bool condition) {
  if (!condition) {
    throw Error(400);
  }
}

bool token(std::string_view value) {
  return !value.empty() && std::all_of(value.begin(), value.end(), [](unsigned char c) {
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
           std::string_view("!#$%&'*+-.^_`|~").find(c) != std::string_view::npos;
  });
}

std::string trim(std::string_view value) {
  while (!value.empty() && (value.front() == ' ' || value.front() == '\t')) {
    value.remove_prefix(1);
  }
  while (!value.empty() && (value.back() == ' ' || value.back() == '\t')) {
    value.remove_suffix(1);
  }
  return std::string(value);
}

std::uint64_t integer(std::string_view value, int base = 10) {
  std::uint64_t result = 0;
  const auto [end, error] =
      std::from_chars(value.data(), value.data() + value.size(), result, base);
  require(!value.empty() && error == std::errc{} && end == value.data() + value.size());
  return result;
}

void framing(Message &message) {
  std::set<std::string> unique;
  for (const auto &[name, value] : message.headers) {
    require(token(name));
    require(std::all_of(value.begin(), value.end(), [](unsigned char c) {
      return c == '\t' || (c >= 32 && c != 127);
    }));
    if (name == "content-length" || name == "transfer-encoding" || name == "host" ||
        name == "expect" || name == "upgrade") {
      require(unique.insert(name).second);
    }
    if (name == "content-length") {
      message.length = integer(value);
    } else if (name == "transfer-encoding") {
      require(lower(value) == "chunked");
      message.chunked = true;
    }
  }
  require(!(message.length && message.chunked));
  message.close = has_token(field(message.headers, "connection"), "close");
  message.websocket = lower(field(message.headers, "upgrade")) == "websocket" &&
                      has_token(field(message.headers, "connection"), "upgrade");
}

} // namespace

capy::task<> race(capy::task<> first, capy::task<> second) {
  Completion state;
  static_cast<void>(co_await capy::when_any(complete(std::move(first), state),
                                            complete(std::move(second), state)));
  if (state.error) {
    std::rethrow_exception(state.error);
  }
}

Error::Error(unsigned value) : std::runtime_error("ingress request failed"), status(value) {
}

std::string lower(std::string_view value) {
  std::string result(value);
  for (auto &c : result) {
    if (c >= 'A' && c <= 'Z') {
      c = static_cast<char>(c + ('a' - 'A'));
    }
  }
  return result;
}

std::string field(const Headers &headers, std::string_view name) {
  std::string result;
  for (const auto &[key, value] : headers) {
    if (key == name) {
      if (!result.empty()) {
        result += ",";
      }
      result += value;
    }
  }
  return result;
}

bool has_token(std::string_view value, std::string_view expected) {
  while (!value.empty()) {
    const auto end = value.find(',');
    if (lower(trim(value.substr(0, end))) == expected) {
      return true;
    }
    if (end == std::string_view::npos) {
      break;
    }
    value.remove_prefix(end + 1);
  }
  return false;
}

std::string authority(std::string_view value) {
  const auto colon = value.find(':');
  if (colon != std::string_view::npos) {
    const auto port = integer(value.substr(colon + 1));
    require(port >= 1 && port <= 65535);
    value = value.substr(0, colon);
  }
  try {
    return egress::normalize_dns_name(value);
  } catch (...) {
    throw Error(400);
  }
}

std::string routing_path(std::string_view target) {
  require(!target.empty() && target.front() == '/' && target.size() <= 8192);
  require(std::all_of(target.begin(), target.end(), [](unsigned char c) {
    return c > 32 && c < 127 && c != '#' && c != '\\';
  }));
  const auto path = target.substr(0, target.find('?'));
  std::string result;
  for (std::size_t i = 0; i < path.size(); ++i) {
    char c = path[i];
    if (c == '%') {
      require(i + 2 < path.size());
      const auto decoded = integer(path.substr(i + 1, 2), 16);
      require(decoded > 32 && decoded < 127 && decoded != '/' && decoded != '\\' &&
              decoded != '%' && decoded != '?' && decoded != '#');
      c = static_cast<char>(decoded);
      i += 2;
    }
    result += c;
  }
  require(result.find("//") == std::string::npos);
  std::size_t start = 1;
  while (start <= result.size()) {
    const auto end = result.find('/', start);
    const auto part =
        std::string_view(result).substr(start, end == std::string::npos ? end : end - start);
    require(part != "." && part != "..");
    if (end == std::string::npos) {
      break;
    }
    start = end + 1;
  }
  return result;
}

void validate_request(Message &message, bool http2) {
  require(token(message.method) && message.method != "CONNECT" && message.method != "TRACE");
  static_cast<void>(routing_path(message.target));
  framing(message);
  if (http2) {
    require(!message.chunked && field(message.headers, "connection").empty() &&
            field(message.headers, "upgrade").empty() &&
            field(message.headers, "keep-alive").empty() &&
            field(message.headers, "proxy-connection").empty());
    const auto host = field(message.headers, "host");
    require(host.empty() || authority(host) == authority(message.host));
  } else {
    message.host = field(message.headers, "host");
    require(!message.host.empty());
    if (!message.length && !message.chunked) {
      message.length = 0;
    }
  }
  message.host = authority(message.host);
  const auto expect = lower(field(message.headers, "expect"));
  if (!expect.empty() && expect != "100-continue") {
    throw Error(417);
  }
  message.expect_continue = expect == "100-continue";
  if (message.websocket) {
    require(!http2 && message.method == "GET" && !message.chunked &&
            message.length.value_or(0) == 0 &&
            field(message.headers, "sec-websocket-version") == "13" &&
            field(message.headers, "sec-websocket-key").size() == 24);
  } else {
    require(field(message.headers, "upgrade").empty());
  }
}

Message parse_head(std::string_view text, bool request) {
  require(text.size() <= header_limit && text.ends_with("\r\n\r\n"));
  Message message;
  const auto first_end = text.find("\r\n");
  auto line = text.substr(0, first_end);
  if (request) {
    const auto space = line.find(' ');
    require(space != std::string_view::npos);
    message.method = line.substr(0, space);
    line.remove_prefix(space + 1);
    const auto version = line.find(' ');
    require(version != std::string_view::npos && line.substr(version + 1) == "HTTP/1.1");
    message.target = line.substr(0, version);
  } else {
    require(line.starts_with("HTTP/1.1 ") || line.starts_with("HTTP/1.0 "));
    require(line.size() >= 12 && (line.size() == 12 || line[12] == ' '));
    message.status = static_cast<unsigned>(integer(line.substr(9, 3)));
    require(message.status >= 100 && message.status <= 599);
  }
  text.remove_prefix(first_end + 2);
  while (text != "\r\n") {
    const auto end = text.find("\r\n");
    require(end != std::string_view::npos && end > 0 && message.headers.size() < 100);
    line = text.substr(0, end);
    const auto colon = line.find(':');
    require(colon != std::string_view::npos && token(line.substr(0, colon)));
    message.headers.emplace_back(lower(line.substr(0, colon)), trim(line.substr(colon + 1)));
    text.remove_prefix(end + 2);
  }
  if (request) {
    validate_request(message, false);
  } else {
    framing(message);
  }
  return message;
}

Headers end_to_end(const Headers &headers) {
  const auto connection = field(headers, "connection");
  const std::set<std::string> removed = {"connection",
                                         "keep-alive",
                                         "proxy-connection",
                                         "proxy-authenticate",
                                         "proxy-authorization",
                                         "te",
                                         "trailer",
                                         "transfer-encoding",
                                         "upgrade"};
  Headers result;
  for (const auto &[name, value] : headers) {
    if (!removed.contains(name) && !has_token(connection, name)) {
      result.emplace_back(name, value);
    }
  }
  return result;
}

Reader::Reader(Wire &value) : wire(value) {
}

capy::task<std::string> Reader::until(std::string_view delimiter, std::size_t limit) {
  while (true) {
    const auto found = pending_.find(delimiter);
    if (found != std::string::npos) {
      require(found + delimiter.size() <= limit);
      auto result = pending_.substr(0, found + delimiter.size());
      pending_.erase(0, found + delimiter.size());
      co_return result;
    }
    if (pending_.size() >= limit) {
      throw Error(431);
    }
    std::array<char, 16384> data{};
    const auto size =
        co_await wire.read(data.data(), std::min(data.size(), limit - pending_.size()));
    if (size == 0) {
      throw Error(400);
    }
    pending_.append(data.data(), size);
  }
}

capy::task<std::string> Reader::head() {
  co_return co_await until("\r\n\r\n", header_limit);
}

capy::task<std::string> Reader::line() {
  co_return co_await until("\r\n", 8192);
}

capy::task<std::string> Reader::read(std::size_t maximum) {
  if (!pending_.empty()) {
    auto result = pending_.substr(0, maximum);
    pending_.erase(0, result.size());
    co_return result;
  }
  std::string result(std::min<std::size_t>(maximum, 16384), '\0');
  const auto size = co_await wire.read(result.data(), result.size());
  result.resize(size);
  co_return result;
}

capy::task<std::string> Reader::exact(std::size_t size) {
  std::string result;
  while (result.size() < size) {
    const auto data = co_await read(size - result.size());
    require(!data.empty());
    result += data;
  }
  co_return result;
}

Body::Body(Reader &reader, const Message &message, bool response)
    : reader_(reader), remaining_(message.length.value_or(0)), chunked_(message.chunked),
      eof_delimited_(response && !message.length && !message.chunked) {
}

capy::task<std::string> Body::read() {
  if (done_) {
    co_return std::string{};
  }
  if (eof_delimited_) {
    co_return co_await reader_.read(16384);
  }
  if (chunked_ && remaining_ == 0) {
    if (chunk_end_) {
      require(co_await reader_.exact(2) == "\r\n");
    }
    auto line = co_await reader_.line();
    line.resize(line.size() - 2);
    const auto extension = line.find(';');
    remaining_ = integer(std::string_view(line).substr(0, extension), 16);
    if (remaining_ == 0) {
      std::size_t trailers = 0;
      while (true) {
        const auto trailer = co_await reader_.line();
        trailers += trailer.size();
        require(trailers <= header_limit);
        if (trailer == "\r\n") {
          break;
        }
        const auto colon = trailer.find(':');
        require(colon != std::string::npos && token(std::string_view(trailer).substr(0, colon)));
        // Trailer fields are consumed but never promoted to routing or framing headers.
      }
      done_ = true;
      co_return std::string{};
    }
    chunk_end_ = true;
  }
  if (remaining_ == 0) {
    done_ = true;
    co_return std::string{};
  }
  auto data =
      co_await reader_.read(static_cast<std::size_t>(std::min<std::uint64_t>(16384, remaining_)));
  require(!data.empty());
  remaining_ -= data.size();
  co_return data;
}

} // namespace zetta_tunnel::ingress
