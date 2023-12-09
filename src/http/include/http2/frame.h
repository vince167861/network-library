#pragma once

#include "shared/stream.h"
#include "shared/task.h"
#include "http2/type.h"
#include "http2/header_packer.h"

#include <cstdint>
#include <string>
#include <list>
#include <memory>
#include <optional>


namespace leaf::network::http2 {


	class frame {
	protected:
		explicit frame(frame_type_t);

	public:
		frame_type_t type;

		virtual void print(std::ostream&) const = 0;

		virtual bool valid() const {
			return true;
		}

		virtual ~frame() = default;

		static std::shared_ptr<frame> parse(stream&);
	};

	std::ostream& operator<<(std::ostream&, const frame&);


	/**
	 * \brief A *potentially* stream-associated frame.
	 */
	class stream_frame: virtual public frame {
	public:
		uint32_t stream_id;

		explicit stream_frame(uint32_t stream_id);
	};


	class headers_based_frame: public stream_frame {
		bool conclude_ = false;

	public:
		std::string pending_fragments;

		explicit headers_based_frame(uint32_t stream_id);

		void add_fragment(std::string_view, bool last_frame);

		header_list_t get_headers(header_packer& decoder) const;

		void set_header(header_packer& encoder, const header_list_t&);
	};


	class data_frame final: public stream_frame {
	public:
		bool end_stream: 1 = false;

		std::optional<uint8_t> padding;

		std::string data;

		explicit data_frame(uint32_t stream_id);

		void print(std::ostream&) const override;
	};


	class headers_frame final: public headers_based_frame {
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

		void print(std::ostream&) const override;
	};


	class priority_frame final: public stream_frame {
	public:
		bool exclusive: 1 = false;

		uint32_t stream_dependence = 0;

		uint8_t weight = 0;

		explicit priority_frame(uint32_t stream_id);

		void print(std::ostream&) const override;
	};


	class rst_stream final: public stream_frame {
	public:
		error_t error_code = error_t::no_error;

		explicit rst_stream(uint32_t stream_id);

		void print(std::ostream&) const override;
	};


	class settings_frame final: public frame {
	public:
		bool ack: 1;

		setting_values_t values;

		settings_frame();

		explicit settings_frame(setting_values_t);

		void print(std::ostream&) const override;
	};


	class push_promise_frame final: public headers_based_frame {
	public:
		uint32_t promised_stream_id;

		explicit push_promise_frame(uint32_t stream_id);

		void print(std::ostream&) const override;
	};


	class ping_frame final: public frame {
	public:
		bool ack: 1;

		uint64_t data;

		void print(std::ostream&) const override;
	};


	class go_away_frame final: public frame {
	public:
		uint32_t last_stream_id;

		error_t error_code;

		std::string additional_data;

		go_away_frame();

		go_away_frame(uint32_t last_stream_id, error_t, std::string_view additional_data = "");

		void print(std::ostream&) const override;
	};


	class window_update_frame final: public stream_frame {
	public:
		uint32_t window_size_increment;

		explicit window_update_frame(uint32_t stream_id);

		void print(std::ostream&) const override;
	};


}
