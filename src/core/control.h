#pragma once

#include "error.h"

#include <string>

namespace st {

Result<std::string> VerifyEgress();
Error SetDesiredMode(const std::string& mode);
Result<std::string> ReadDesiredMode();

}  // namespace st
