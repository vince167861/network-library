#include "http2/request.h"

#include "http2/frame.h"
#include "utils.h"

namespace leaf::network::http2 {

	request::request(std::string method, url target, std::list<std::pair<std::string, std::string>> headers)
		: method(std::move(method)), request_url(std::move(target)) {
		this->headers = std::move(headers);
	}

	void request::from_push_promise(header_list_t headers) {
		for (auto ptr = headers.begin(); ptr != headers.end();) {
			const auto current = ptr++;
			if (current->first == ":method")
				method = current->second;
			else if (current->first == ":scheme")
				request_url.scheme = current->second;
			else if (current->first == ":path")
				request_url.path = current->second;
			else if (current->first == ":authority")
				request_url.host = current->second;
			else
				continue;
			headers.erase(current);
		}
		this->headers = std::move(headers);
	}

	std::list<std::shared_ptr<frame>>
	request::build(const uint32_t stream_id, header_packer& packer, const uint32_t max_frame_size) const {
		std::list<std::shared_ptr<frame>> frames;
		auto copy = headers;
		std::string path = request_url.path.empty() ? "/" : request_url.path;
		if (!request_url.query.empty())
			path = path + '?' + to_url_encoded(request_url.query);
		copy.emplace_front(":path", std::move(path));
		copy.emplace_front(":method", method);
		copy.emplace_front(":authority", request_url.host);
		copy.emplace_front(":scheme", request_url.scheme);

		auto fields = packer.encode(copy);
		auto ptr = fields.begin();
		{
			const auto frame_size
					= std::min<std::size_t>(max_frame_size, std::distance(ptr, fields.end()));
			auto hf = std::make_shared<headers_frame>(stream_id);
			const auto begin = ptr;
			std::advance(ptr, frame_size);
			hf->end_stream = body.empty();
			hf->end_headers = ptr == fields.end();
			hf->field_block_fragments = {begin, ptr};
			frames.emplace_back(hf);
		}
		while (ptr != fields.end()) {
			const auto frame_size
					= std::min<std::size_t>(max_frame_size, std::distance(ptr, fields.end()));
			auto cf = std::make_shared<continuation_frame>(stream_id);
			const auto begin = ptr;
			std::advance(ptr, frame_size);
			cf->end_headers = ptr == fields.end();
			cf->field_block_fragments = {begin, ptr};
			frames.emplace_back(cf);
		}
		if (!body.empty()) {
			auto data_f = std::make_shared<data_frame>(stream_id);
			data_f->data = body;
			data_f->end_stream = true;
			frames.emplace_back(data_f);
		}
		return frames;
	}
}
