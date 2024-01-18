#include "http2/stream.h"
#include "http2/context.h"

#include <ranges>

namespace leaf::network::http2 {

	const std::runtime_error
	illegal_stream_id{"Illegal stream identifier."};

	stream_id_t context::next_remote_stream_id() {
		if (remote_config.last_open_stream == 0)
			switch (endpoint_type) {
				case endpoint_type_t::client: remote_config.last_open_stream = 2; break;
				case endpoint_type_t::server: remote_config.last_open_stream = 1; break;
				default: throw std::runtime_error{"unimplemented"};
			}
		else
			remote_config.last_open_stream += 2;
		return remote_config.last_open_stream;
	}

	stream_id_t context::next_local_stream_id() {
		if (local_config.last_open_stream == 0)
			switch (endpoint_type) {
				case endpoint_type_t::client:
					local_config.last_open_stream = 1;
				break;
				case endpoint_type_t::server:
					local_config.last_open_stream = 2;
				break;
			}
		else
			local_config.last_open_stream += 2;
		return local_config.last_open_stream;
	}

	void context::update_remote_config(const setting_values_t& values) {
		for (auto& [s, v]: values)
			switch (s) {
				case settings_t::max_concurrent_stream:
					remote_config.max_concurrent_streams = v; break;
				case settings_t::header_table_size:
					remote_config.header_table_size = v; break;
				case settings_t::enable_push:
					if (v > 1)
						throw std::exception{}; // TODO: Use custom exception
					remote_config.enable_push = v == 1;
					break;
				case settings_t::initial_window_size:
					if (static_cast<int32_t>(v) < 0)
						throw std::exception{}; // TODO: Use custom exception
					remote_config.init_window_size = v;
					break;
				case settings_t::max_frame_size:
					remote_config.max_frame_size = v;
					break;
				case settings_t::max_header_list_size:
					break;
			}
	}

	setting_values_t context::pack_settings() const {
		return {
				{settings_t::max_concurrent_stream, local_config.max_concurrent_streams},
				{settings_t::header_table_size, local_config.header_table_size},
				{settings_t::enable_push, local_config.enable_push}
		};
	}

	stream_handler& context::get_stream(const stream_id_t stream_id) {
		if (handlers_.contains(stream_id))
			return *handlers_.at(stream_id);
		throw illegal_stream_id;
	}

	void context::remote_closing(uint32_t last_stream_id) {
		erase_if(handlers_, [&](auto& p){ return p.first > last_stream_id; });
	}

	context::context(const endpoint_type_t t)
		: endpoint_type(t) {
	}

	void context::add_task(const std::coroutine_handle<> handle) {
		tasks_.push_back(handle);
	}

	bool context::process_tasks() {
		bool done = true;
		for (auto& t: tasks_) {
			if (t.done())
				continue;
			t();
			if (!t.done())
				done = false;
		}
		return done;
	}

	bool context::has_pending_streams() const {
		for (const auto& handler: handlers_ | std::views::values)
			if (const auto st = handler->state(); st != stream_handler::state_t::closed)
				return true;
		return false;
	}

	void context::register_handler(std::unique_ptr<stream_handler> handler) {
		*handlers_.insert_or_assign(handler->stream_id(), std::move(handler)).first->second;
	}
}
