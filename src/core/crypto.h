#pragma once

#include "error.h"

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace st {

Result<std::vector<std::uint8_t>> Base64Decode(std::string_view text);
std::string Base64Encode(const std::uint8_t* data, std::size_t size);

Error AssertRsaPublicKeyXml(const std::string& xml);
Error VerifyRsaSha256(const std::string& xml_public_key, const std::uint8_t* data, std::size_t size,
                      const std::uint8_t* signature, std::size_t signature_size);
Result<std::vector<std::uint8_t>> SignRsaSha256(std::string_view modulus_b64, std::string_view d_b64,
                                                const std::uint8_t* data, std::size_t size);

}  // namespace st
