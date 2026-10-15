#include "ingress.hpp"

#include <boost/capy/ex/async_event.hpp>
#include <boost/capy/ex/run_async.hpp>
#include <boost/capy/when_any.hpp>
#include <nghttp2/nghttp2.h>

#include <array>
#include <cstring>
#include <deque>

namespace zetta_tunnel::ingress {
namespace {

void check(int result) {
  if (result < 0) {
    throw Error(502);
  }
}

capy::task<> wait(capy::async_event &event) {
  auto [error] = co_await event.wait();
  if (error) {
    throw Error(502);
  }
}

} // namespace

struct Http2::Impl {
  struct Stream final : Exchange {
    Stream(Impl &owner, std::int32_t value) : connection(owner), id(value) {
    }

    Impl &connection;
    std::int32_t id;
    capy::async_event changed;
    std::stop_source stop;
    std::deque<std::string> input;
    std::string output;
    std::size_t buffered = 0;
    std::size_t header_bytes = 0;
    bool headers_done = false;
    bool input_done = false;
    bool output_done = false;
    bool closed = false;
    bool responded = false;

    capy::task<std::string> read_body() override {
      while (input.empty() && !input_done && !closed) {
        changed.clear();
        co_await wait(changed);
      }
      if (closed || connection.closed) {
        throw Error(502);
      }
      if (input.empty()) {
        co_return std::string{};
      }
      auto data = std::move(input.front());
      input.pop_front();
      buffered -= data.size();
      check(nghttp2_session_consume(connection.session.get(), id, data.size()));
      connection.writable.set();
      co_return data;
    }

    capy::task<> send_head(unsigned status, Headers headers) override {
      if (closed || connection.closed || responded) {
        throw Error(502);
      }
      headers.insert(headers.begin(), {":status", std::to_string(status)});
      std::vector<nghttp2_nv> values;
      for (auto &[name, value] : headers) {
        values.push_back({reinterpret_cast<std::uint8_t *>(name.data()),
                          reinterpret_cast<std::uint8_t *>(value.data()), name.size(), value.size(),
                          NGHTTP2_NV_FLAG_NONE});
      }
      if (status < 200) {
        check(nghttp2_submit_headers(connection.session.get(), NGHTTP2_FLAG_NONE, id, nullptr,
                                     values.data(), values.size(), nullptr));
      } else {
        nghttp2_data_provider provider{};
        provider.source.ptr = this;
        provider.read_callback = provide;
        check(nghttp2_submit_response(connection.session.get(), id, values.data(), values.size(),
                                      &provider));
        responded = true;
      }
      connection.writable.set();
      co_return;
    }

    capy::task<> send_body(std::string data) override {
      if (closed || connection.closed || data.size() > 16384 || !output.empty()) {
        throw Error(502);
      }
      output = std::move(data);
      static_cast<void>(nghttp2_session_resume_data(connection.session.get(), id));
      connection.writable.set();
      while (!output.empty() && !closed && !connection.closed) {
        changed.clear();
        co_await wait(changed);
      }
      if (closed || connection.closed) {
        throw Error(502);
      }
    }

    capy::task<> finish() override {
      output_done = true;
      static_cast<void>(nghttp2_session_resume_data(connection.session.get(), id));
      connection.writable.set();
      co_return;
    }

    void abort() override {
      if (!closed && !connection.closed) {
        static_cast<void>(nghttp2_submit_rst_stream(connection.session.get(), NGHTTP2_FLAG_NONE, id,
                                                    NGHTTP2_CANCEL));
        connection.writable.set();
        closed = true;
        stop.request_stop();
        changed.set();
      }
    }

    static ssize_t provide(nghttp2_session *, std::int32_t, std::uint8_t *buffer,
                           std::size_t length, std::uint32_t *flags, nghttp2_data_source *source,
                           void *) noexcept {
      auto &stream = *static_cast<Stream *>(source->ptr);
      if (stream.output.empty() && !stream.output_done) {
        return NGHTTP2_ERR_DEFERRED;
      }
      const auto size = std::min(length, stream.output.size());
      std::memcpy(buffer, stream.output.data(), size);
      stream.output.erase(0, size);
      if (stream.output.empty()) {
        if (stream.output_done) {
          *flags |= NGHTTP2_DATA_FLAG_EOF;
        }
        stream.changed.set();
      }
      return static_cast<ssize_t>(size);
    }
  };

  Wire &wire;
  corosio::io_context &context;
  Handler handler;
  std::unique_ptr<nghttp2_session, decltype(&nghttp2_session_del)> session{nullptr,
                                                                           nghttp2_session_del};
  std::map<std::int32_t, std::shared_ptr<Stream>> streams;
  std::vector<std::shared_ptr<Stream>> pending;
  capy::async_event writable;
  capy::async_event workers_done;
  std::map<std::int32_t, std::shared_ptr<Stream>> workers;
  bool closed = false;

  Impl(Wire &value, corosio::io_context &io, Handler callback)
      : wire(value), context(io), handler(std::move(callback)) {
    nghttp2_session_callbacks *raw_callbacks = nullptr;
    check(nghttp2_session_callbacks_new(&raw_callbacks));
    std::unique_ptr<nghttp2_session_callbacks, decltype(&nghttp2_session_callbacks_del)> callbacks(
        raw_callbacks, nghttp2_session_callbacks_del);
    nghttp2_session_callbacks_set_on_begin_headers_callback(callbacks.get(), begin_headers);
    nghttp2_session_callbacks_set_on_header_callback(callbacks.get(), header);
    nghttp2_session_callbacks_set_on_frame_recv_callback(callbacks.get(), frame);
    nghttp2_session_callbacks_set_on_frame_send_callback(callbacks.get(), sent);
    nghttp2_session_callbacks_set_on_data_chunk_recv_callback(callbacks.get(), data);
    nghttp2_session_callbacks_set_on_stream_close_callback(callbacks.get(), close_stream);
    nghttp2_option *raw_options = nullptr;
    check(nghttp2_option_new(&raw_options));
    std::unique_ptr<nghttp2_option, decltype(&nghttp2_option_del)> options(raw_options,
                                                                           nghttp2_option_del);
    nghttp2_option_set_no_auto_window_update(options.get(), 1);
    nghttp2_option_set_max_outbound_ack(options.get(), 32);
    nghttp2_option_set_max_continuations(options.get(), 8);
    nghttp2_session *raw_session = nullptr;
    check(nghttp2_session_server_new2(&raw_session, callbacks.get(), this, options.get()));
    session.reset(raw_session);
    const nghttp2_settings_entry settings[] = {
        {NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, 32},
        {NGHTTP2_SETTINGS_MAX_HEADER_LIST_SIZE, header_limit},
        {NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE, buffer_limit},
        {NGHTTP2_SETTINGS_HEADER_TABLE_SIZE, 4096}};
    check(nghttp2_submit_settings(session.get(), NGHTTP2_FLAG_NONE, settings, std::size(settings)));
    writable.set();
  }

  static int begin_headers(nghttp2_session *, const nghttp2_frame *frame, void *user) noexcept {
    auto &self = *static_cast<Impl *>(user);
    try {
      if (frame->headers.cat != NGHTTP2_HCAT_REQUEST || self.streams.size() >= 32 ||
          self.workers.size() + self.pending.size() >= 32) {
        return NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE;
      }
      self.streams.emplace(frame->hd.stream_id,
                           std::make_shared<Stream>(self, frame->hd.stream_id));
      return 0;
    } catch (...) {
      return NGHTTP2_ERR_CALLBACK_FAILURE;
    }
  }

  static int header(nghttp2_session *, const nghttp2_frame *frame, const std::uint8_t *name,
                    std::size_t name_length, const std::uint8_t *value, std::size_t value_length,
                    std::uint8_t, void *user) noexcept {
    auto &self = *static_cast<Impl *>(user);
    try {
      const auto found = self.streams.find(frame->hd.stream_id);
      if (found == self.streams.end()) {
        return NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE;
      }
      auto &stream = *found->second;
      stream.header_bytes += name_length + value_length;
      if (stream.header_bytes > header_limit || stream.request.headers.size() >= 100) {
        return NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE;
      }
      std::string key(reinterpret_cast<const char *>(name), name_length);
      std::string text(reinterpret_cast<const char *>(value), value_length);
      if (key == ":method") {
        stream.request.method = text;
      } else if (key == ":path") {
        stream.request.target = text;
      } else if (key == ":authority") {
        stream.request.host = text;
      } else if (key == ":scheme") {
        if (text != "https") {
          return NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE;
        }
      } else if (key.starts_with(':')) {
        return NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE;
      } else {
        stream.request.headers.emplace_back(std::move(key), std::move(text));
      }
      return 0;
    } catch (...) {
      return NGHTTP2_ERR_CALLBACK_FAILURE;
    }
  }

  static int frame(nghttp2_session *, const nghttp2_frame *frame, void *user) noexcept {
    auto &self = *static_cast<Impl *>(user);
    try {
      const auto found = self.streams.find(frame->hd.stream_id);
      if (found == self.streams.end()) {
        return 0;
      }
      auto &stream = *found->second;
      if (frame->hd.type == NGHTTP2_HEADERS && !stream.headers_done) {
        stream.headers_done = true;
        self.pending.push_back(found->second);
      }
      if ((frame->hd.type == NGHTTP2_HEADERS || frame->hd.type == NGHTTP2_DATA) &&
          (frame->hd.flags & NGHTTP2_FLAG_END_STREAM)) {
        stream.input_done = true;
        stream.changed.set();
      }
      return 0;
    } catch (...) {
      return NGHTTP2_ERR_CALLBACK_FAILURE;
    }
  }

  static int data(nghttp2_session *, std::uint8_t, std::int32_t id, const std::uint8_t *data,
                  std::size_t length, void *user) noexcept {
    auto &self = *static_cast<Impl *>(user);
    try {
      const auto found = self.streams.find(id);
      if (found == self.streams.end()) {
        return 0;
      }
      auto &stream = *found->second;
      if (stream.buffered + length > buffer_limit || stream.input.size() >= 1024) {
        return NGHTTP2_ERR_CALLBACK_FAILURE;
      }
      if (length != 0) {
        stream.input.emplace_back(reinterpret_cast<const char *>(data), length);
        stream.buffered += length;
        stream.changed.set();
      }
      return 0;
    } catch (...) {
      return NGHTTP2_ERR_CALLBACK_FAILURE;
    }
  }

  static int sent(nghttp2_session *session, const nghttp2_frame *frame, void *user) noexcept {
    auto &self = *static_cast<Impl *>(user);
    const auto found = self.streams.find(frame->hd.stream_id);
    if (found != self.streams.end() && !found->second->input_done &&
        (frame->hd.type == NGHTTP2_DATA || frame->hd.type == NGHTTP2_HEADERS) &&
        (frame->hd.flags & NGHTTP2_FLAG_END_STREAM)) {
      // An early response is complete: stop an unfinished upload and release its window.
      static_cast<void>(nghttp2_submit_rst_stream(session, NGHTTP2_FLAG_NONE, frame->hd.stream_id,
                                                  NGHTTP2_NO_ERROR));
    }
    return 0;
  }

  static int close_stream(nghttp2_session *session, std::int32_t id, std::uint32_t,
                          void *user) noexcept {
    auto &self = *static_cast<Impl *>(user);
    const auto found = self.streams.find(id);
    if (found != self.streams.end()) {
      auto &stream = *found->second;
      // Return unused connection credit so one reset cannot starve other streams.
      static_cast<void>(nghttp2_session_consume_connection(session, stream.buffered));
      stream.closed = true;
      stream.stop.request_stop();
      stream.changed.set();
      self.streams.erase(found);
    }
    return 0;
  }

  void launch_pending() {
    auto ready = std::move(pending);
    pending.clear();
    for (auto &stream : ready) {
      if (stream->closed) {
        continue;
      }
      if (stream->input_done && stream->input.empty() &&
          field(stream->request.headers, "content-length").empty()) {
        stream->request.length = 0;
      }
      workers.emplace(stream->id, stream);
      auto complete = [this, stream] {
        workers.erase(stream->id);
        workers_done.set();
      };
      capy::run_async(context.get_executor(), stream->stop.get_token(), complete,
                      [complete, stream](std::exception_ptr) {
                        stream->abort();
                        complete();
                      })(handler(stream));
    }
  }

  capy::task<> read_loop() {
    std::array<char, 16384> buffer{};
    while (!closed) {
      const auto size = co_await wire.read(buffer.data(), buffer.size());
      if (size == 0) {
        co_return;
      }
      const auto result = nghttp2_session_mem_recv(
          session.get(), reinterpret_cast<const std::uint8_t *>(buffer.data()), size);
      if (result < 0 || static_cast<std::size_t>(result) != size) {
        throw Error(400);
      }
      launch_pending();
      writable.set();
    }
  }

  capy::task<> write_loop() {
    while (!closed) {
      co_await wait(writable);
      writable.clear();
      while (true) {
        const std::uint8_t *data = nullptr;
        const auto size = nghttp2_session_mem_send(session.get(), &data);
        if (size < 0) {
          throw Error(502);
        }
        if (size == 0) {
          break;
        }
        const std::string buffer(reinterpret_cast<const char *>(data),
                                 static_cast<std::size_t>(size));
        co_await wire.write(buffer);
      }
    }
  }

  capy::task<> run() {
    try {
      co_await race(read_loop(), write_loop());
    } catch (...) {
    }
    closed = true;
    for (const auto &[id, stream] : workers) {
      stream->closed = true;
      stream->stop.request_stop();
      stream->changed.set();
    }
    while (!workers.empty()) {
      workers_done.clear();
      // This task is not canceled by the connection's worker token. It owns worker teardown.
      co_await wait(workers_done);
    }
  }
};

Http2::Http2(Wire &wire, corosio::io_context &context, Handler handler)
    : impl_(std::make_unique<Impl>(wire, context, std::move(handler))) {
}

Http2::~Http2() = default;

capy::task<> Http2::run() {
  co_await impl_->run();
}

} // namespace zetta_tunnel::ingress
