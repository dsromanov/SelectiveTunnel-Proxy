#pragma once

#include "error.h"

#include <nlohmann/json.hpp>

#include <filesystem>
#include <string>

namespace st {

struct EngineHandle {
    void* process = nullptr;
    void* job = nullptr;
    unsigned long pid = 0;
    bool running() const;
};

Error StartEngineMemory(const nlohmann::json& config, const std::filesystem::path& engine, EngineHandle& handle,
                        const std::string& mode = "run");
void StopEngineMemory(EngineHandle& handle);
Error TestEngineConfig(const nlohmann::json& config, const std::filesystem::path& engine);
void KillOwnEngine(const std::filesystem::path& engine);

}  // namespace st
