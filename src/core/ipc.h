#pragma once

#include "error.h"

#include <atomic>
#include <nlohmann/json.hpp>
#include <string>

namespace st {

using IpcHandler = nlohmann::json (*)(const nlohmann::json&);

Error SendIpc(const nlohmann::json& request, nlohmann::json& response, unsigned timeout_ms = 30000);
void RunPipeServer(std::atomic<bool>& stop, IpcHandler handler);

}  // namespace st
