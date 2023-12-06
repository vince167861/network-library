#pragma once

#include "shared/stream.h"
#include "type.h"

#include <cstdint>
#include <string>
#include <list>
#include <memory>
#include <optional>

namespace leaf::network::http2 {

	class context;


	class frame {
	protected:
		explicit frame(frame_type_t);

	public:
		frame_type_t type;

		virtual void send(stream& out) const = 0;

		virtual void print(std::ostream&) const = 0;

		virtual ~frame() = default;

		static std::shared_ptr<frame> parse(stream&);
	};

	std::ostream& operator<<(std::ostream&, const frame&);


	/**
	 * \brief A *potentially* stream-associated frame.
	 */
	class stream_frame: public frame {
	public:
		uint32_t stream_id;

		stream_frame(frame_type_t, uint32_t stream_id);
	};


	class data_frame final: public stream_frame {
	public:
		bool end_stream: 1 = false;

		std::optional<uint8_t> padding;

		std::string data;

		explicit data_frame(uint32_t stream_id);

		explicit data_frame(std::string_view);

		void send(stream& out) const override;

		void print(std::ostream&) const override;
	};


	class headers_info_frame: public stream_frame {
	protected:
		headers_info_frame(frame_type_t, uint32_t stream_id);

	public:
		bool end_headers: 1 = false;

		std::string field_block_fragments;
	};


	class headers_frame final: public headers_info_frame {
	public:
		struct priority_t {
			bool exclusive: 1;
			uint32_t dependency;
			uint8_t weight;
		};

		bool end_stream: 1 = false;

		std::optional<priority_t> priority;

		std::optional<uint8_t> padding;

		explicit headers_frame(uint32_t stream_id);

		explicit headers_frame(std::string_view);

		void send(stream& out) const override;

		void print(std::ostream&) const override;
	};


	class priority_frame final: public stream_frame {
	public:
		bool exclusive: 1 = false;

		uint32_t stream_dependence = 0;

		uint8_t weight = 0;

		explicit priority_frame(uint32_t stream_id);

		void send(stream& out) const override;

		void print(std::ostream&) const override;
	};


	class rst_stream final: public stream_frame {
	public:
		error_t error_code;

		explicit rst_stream(std::string_view);

		explicit rst_stream(uint32_t stream_id, error_t);

		void send(stream& out) const override;

		void print(std::ostream&) const override;
	};


	class settings_frame final: public frame {
	public:
		bool ack: 1;

		std::list<std::pair<settings_t, uint32_t>> values;

		settings_frame();

		explicit settings_frame(std::list<std::pair<settings_t, uint32_t>>);

		explicit settings_frame(std::string_view);

		void send(stream& out) const override;

		void print(std::ostream&) const override;
	};


	class push_promise_frame final: public stream_frame {
	public:
		uint32_t promised_stream_id;

		std::string field_block_fragments;

		explicit push_promise_frame(std::string_view);

		void send(stream& out) const override;

		void print(std::ostream&) const override;
	};


	class ping_frame final: public frame {
	public:
		bool ack: 1;

		uint64_t data;

		void send(stream& out) const override;

		void print(std::ostream&) const override;
	};


	class go_away_frame: public frame {
	public:
		uint32_t last_stream_id;

		error_t error_code;

		std::string additional_data;

		go_away_frame(std::string_view);

		go_away_frame(uint32_t last_stream_id, error_t, std::string_view additional_data = "");

		void send(stream&) const override;

		void print(std::ostream&) const override;
	};


	class window_update_frame final: public stream_frame {
	public:
		uint32_t window_size_increment;

		explicit window_update_frame(std::string_view);

		void send(stream& out) const override;

		void print(std::ostream&) const override;
	};


	class continuation_frame final: public headers_info_frame {
	public:
		explicit continuation_frame(uint32_t stream_id);

		explicit continuation_frame(std::string_view);

		void send(stream& out) const override;

		void print(std::ostream&) const override;
	};
}
