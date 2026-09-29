#include "json_io.h"

#include "util.h"

namespace st {

Result<nlohmann::json> ReadJsonFile(const std::filesystem::path& path) {
    auto text = ReadTextFile(path);
    if (!text) {
        return Result<nlohmann::json>::fail(text.error.message);
    }
    try {
        return Result<nlohmann::json>::ok(nlohmann::json::parse(text.value));
    } catch (const std::exception& ex) {
        return Result<nlohmann::json>::fail(std::string("Invalid JSON: ") + ex.what());
    }
}

Error WriteJsonAtomic(const std::filesystem::path& path, const nlohmann::json& value) {
    return WriteTextAtomic(path, value.dump(2));
}

}  // namespace st
