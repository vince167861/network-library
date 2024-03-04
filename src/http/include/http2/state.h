#pragma once
#include "http/message.h"
#include "http2/frame.h"
#include "http2/type.h"
#include "http2/header_packer.h"
#include "basic_endpoint.h"
#include <list>
#include <map>
#include <memory>
#include <future>

namespace network::http2 {

	struct stream_state;

	struct connection_state {

		const endpoint_type type;

		endpoint_state_t local_config, remote_config;

		std::size_t remote_window_size, local_window_size;

		header_packer local_packer, remote_packer;

		connection_state(const endpoint_type __t, stream& __s)
				: type(__t), pipe_(__s) {
		}

		std::future<http::response> remote_reserve(stream_id_t, http::fields);

		void local_reserve(http::fields);

		void remote_open(http::fields);

		std::future<http::response> local_open(http::request);

		void update_remote_settings(const setting_values_t&);

		[[nodiscard]] setting_values_t pack_local_settings() const;

		stream_state& operator[](stream_id_t);

		void remote_close(stream_id_t last);

		void local_close(error_t = error_t::no_error);

		bool has_pending_streams() const;

		void write(const connection_frame&);

		void task_add(frame_generator handle);

		bool task_process();

	private:
		std::map<stream_id_t, std::unique_ptr<stream_state>> streams_;

		std::list<frame_generator> tasks_;

		stream& pipe_;

		stream_id_t next_remote_stream_id();

		stream_id_t next_local_stream_id();
	};


	struct stream_state final {

		enum class state_t {
			idle, local_reserved, remote_reserved, open, local_half_closed, remote_half_closed, closed
		};

		const stream_id_t stream_id;

		/// constructor for local open (request) stream
		stream_state(stream_id_t, ostream&, connection_state&, http::request);

		/// constructor for remote reserve (server push) stream
		stream_state(stream_id_t, ostream&, connection_state&, http::fields);

		void notify(http::fields, bool end_stream);

		void notify(byte_string_view, bool end_stream);

		void remote_reset(error_t);

		void local_close();

		void increase_window(std::uint32_t);

		std::size_t available_window() const;

		bool request_window(std::size_t);

		state_t state() const;

		void write(const stream_frame&);

		auto response() {
			return response_promise_.get_future();
		}

	private:

		state_t state_;

		connection_state& connection_;

		ostream& out_;

		http::request request_;

		http::response pending_response_;

		std::promise<http::response> response_promise_;

		std::uint32_t window_size_;

		std::list<std::reference_wrapper<stream_state>> promised_stream_;

		void set_local_closed_();

		void set_remote_closed_();

	};
}
