#include "http2/response.h"

namespace leaf::network::http2 {
	void response::print(std::ostream& s) const {
		s << "Response " << std::dec << status << '\n';
		if (headers.empty())
			s << "\t(No header)\n";
		else for (auto& [key, value]: headers)
			s << "\t" << key << ": " << value << '\n';
		s << body << '\n';
	}
}
