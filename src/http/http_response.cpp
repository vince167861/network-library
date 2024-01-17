#include "http/response.h"

namespace leaf::network::http {

	bool response::is_redirection() const {
		return 300 <= status && status <= 399;
	}
}
