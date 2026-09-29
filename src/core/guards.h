#pragma once

#include "error.h"
#include "policy.h"

#include <string>
#include <vector>

namespace st {

Error SetGuards(const Policy& policy, bool flush_dns = true);
Error RemoveGuards();
Error RemoveLegacyFakeIpRoutes();
std::string DetectBindInterface();
std::vector<std::string> DetectHappHints();

}  // namespace st
