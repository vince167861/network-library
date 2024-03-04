#include "http2/state.h"
#include <ranges>
#include <iostream>

constexpr auto illegal_stream_id("illegal stream id");

namespace network::http2 {

	std::future<http::response> connection_state::remote_reserve(const stream_id_t __id, http::fields __f) {
		if (next_remote_stream_id() != __id)
			throw connection_error(error_t::protocol_error, "remote reserved invalid stream");
		auto __state = std::make_unique<stream_state>(__id, pipe_, *this, std::move(__f));
		auto f = __state->response();
		streams_.emplace(__id, std::move(__state));
		return f;
	}

	std::future<http::response> connection_state::local_open(http::request __req) {
		auto __state = std::make_unique<stream_state>(next_local_stream_id(), pipe_, *this, std::move(__req));
		auto f = __state->response();
		const auto __id = __state->stream_id;
		streams_.emplace(__id, std::move(__state));
		return f;
	}

	void connection_state::update_remote_settings(const setting_values_t& values) {
		for (auto& [s, v]: values)
			switch (s) {
				case settings_t::max_concurrent_stream:
					remote_config.max_concurrent_streams = v; break;
				case settings_t::header_table_size:
					remote_config.header_table_size = v; break;
				case settings_t::enable_push:
					if (v > 1)
						throw connection_error(error_t::protocol_error,
							std::format("SETTINGS_ENABLE_PUSH expect: 0..1; actual: {}", v));
					remote_config.enable_push = v == 1;
					break;
				case settings_t::initial_window_size:
					if (static_cast<std::int32_t>(v) < 0)
						throw connection_error(error_t::flow_control_error, std::format("SETTINGS_INITIAL_WINDOW_SIZE expect: 0..2^31-1; actual: {}", v));
					remote_config.init_window_size = v;
					break;
				case settings_t::max_frame_size:
					if (v > 1u << 24 - 1 || v < 1u << 14)
						throw connection_error(error_t::protocol_error, std::format("SETTINGS_INITIAL_WINDOW_SIZE expect: 2^14-1..2^24-1; actual: {}", v));
					remote_config.max_frame_size = v;
					break;
				case settings_t::max_header_list_size:
					break;
			}
	}

	setting_values_t connection_state::pack_local_settings() const {
		return {
				{settings_t::max_concurrent_stream, local_config.max_concurrent_streams},
				{settings_t::header_table_size, local_config.header_table_size},
				{settings_t::enable_push, local_config.enable_push}
		};
	}

	stream_state& connection_state::operator[](const stream_id_t __id) {
		if (streams_.contains(__id))
			return *streams_.at(__id);
		throw std::runtime_error(illegal_stream_id);
	}

	void connection_state::remote_close(const stream_id_t __last) {
		erase_if(streams_, [&](auto& p){ return p.first > __last; });
	}

	void connection_state::local_close(const error_t __err) {
		write(go_away(local_config.last_open_stream, __err));
	}

	bool connection_state::has_pending_streams() const {
		for (const auto& handler: streams_ | std::views::values)
			if (const auto st = handler->state(); st != stream_state::state_t::closed)
				return true;
		return false;
	}

	void connection_state::write(const connection_frame& __f) {
		std::cout << std::format("[HTTP/2] sending {}\n", static_cast<const basic_frame&>(__f));
		__f.generator(pipe_, *this);
	}

	void connection_state::task_add(const frame_generator handle) {
		tasks_.push_back(handle);
	}

	bool connection_state::task_process() {
		if (tasks_.empty())
			return true;
		auto __t = tasks_.front();
		tasks_.pop_front();
		__t();
		if (!__t.done())
			tasks_.push_back(__t);
		return tasks_.empty();
	}

	stream_id_t connection_state::next_remote_stream_id() {
		if (remote_config.last_open_stream == 0)
			switch (type) {
				case endpoint_type::client: remote_config.last_open_stream = 2; break;
				case endpoint_type::server: remote_config.last_open_stream = 1; break;
				default: throw std::runtime_error{"unimplemented"};
			}
		else
			remote_config.last_open_stream += 2;
		return remote_config.last_open_stream;
	}

	stream_id_t connection_state::next_local_stream_id() {
		if (local_config.last_open_stream == 0)
			switch (type) {
				case endpoint_type::client:
					local_config.last_open_stream = 1;
				break;
				case endpoint_type::server:
					local_config.last_open_stream = 2;
				break;
			}
		else
			local_config.last_open_stream += 2;
		return local_config.last_open_stream;
	}
}
