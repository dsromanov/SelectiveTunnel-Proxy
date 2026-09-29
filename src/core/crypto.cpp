#include "crypto.h"

#include "sha256.h"

#include <algorithm>
#include <cctype>

namespace st {
namespace {

using Limb = std::uint32_t;
using Big = std::vector<Limb>;

int B64Value(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

void Trim(Big& n) {
    while (n.size() > 1 && n.back() == 0) {
        n.pop_back();
    }
}

int Cmp(const Big& a, const Big& b) {
    if (a.size() != b.size()) {
        return a.size() > b.size() ? 1 : -1;
    }
    for (std::size_t i = a.size(); i-- > 0;) {
        if (a[i] != b[i]) {
            return a[i] > b[i] ? 1 : -1;
        }
    }
    return 0;
}

Big FromBe(const std::uint8_t* data, std::size_t size) {
    Big n((size + 3) / 4, 0);
    for (std::size_t i = 0; i < size; ++i) {
        const std::size_t ri = size - 1 - i;
        n[ri / 4] |= static_cast<Limb>(data[i]) << ((ri % 4) * 8);
    }
    Trim(n);
    return n;
}

std::vector<std::uint8_t> ToBe(const Big& n, std::size_t size) {
    std::vector<std::uint8_t> out(size, 0);
    for (std::size_t i = 0; i < n.size(); ++i) {
        for (int b = 0; b < 4; ++b) {
            const std::size_t idx = i * 4 + b;
            if (idx >= size) {
                continue;
            }
            out[size - 1 - idx] = static_cast<std::uint8_t>((n[i] >> (8 * b)) & 0xff);
        }
    }
    return out;
}

void SubFrom(Big& a, const Big& b) {
    std::uint64_t borrow = 0;
    for (std::size_t i = 0; i < a.size(); ++i) {
        const std::uint64_t bb = i < b.size() ? b[i] : 0;
        const std::uint64_t cur = static_cast<std::uint64_t>(a[i]) - bb - borrow;
        a[i] = static_cast<Limb>(cur);
        borrow = (cur >> 63) & 1;
    }
}

Big MulLimb(const Big& a, Limb m) {
    Big r(a.size() + 1, 0);
    std::uint64_t carry = 0;
    for (std::size_t i = 0; i < a.size(); ++i) {
        const std::uint64_t cur = static_cast<std::uint64_t>(a[i]) * m + carry;
        r[i] = static_cast<Limb>(cur);
        carry = cur >> 32;
    }
    r[a.size()] = static_cast<Limb>(carry);
    Trim(r);
    return r;
}

void AddShifted(Big& acc, const Big& v, std::size_t shift) {
    if (acc.size() < v.size() + shift + 1) {
        acc.resize(v.size() + shift + 1, 0);
    }
    std::uint64_t carry = 0;
    for (std::size_t i = 0; i < v.size() || carry; ++i) {
        const std::uint64_t cur =
            static_cast<std::uint64_t>(acc[i + shift]) + (i < v.size() ? v[i] : 0) + carry;
        acc[i + shift] = static_cast<Limb>(cur);
        carry = cur >> 32;
    }
    Trim(acc);
}

Big Mul(const Big& a, const Big& b) {
    Big r(a.size() + b.size() + 1, 0);
    for (std::size_t i = 0; i < a.size(); ++i) {
        AddShifted(r, MulLimb(b, a[i]), i);
    }
    Trim(r);
    return r;
}

Big Mod(Big a, const Big& m) {
    if (Cmp(a, m) < 0) {
        return a;
    }
    const std::size_t shift = (a.size() - m.size()) * 32;
    for (int bit = static_cast<int>(shift) + 31; bit >= 0; --bit) {
        Big t = m;
        const std::size_t limb_shift = static_cast<std::size_t>(bit) / 32;
        const int rem = bit % 32;
        Big shifted(t.size() + limb_shift + 1, 0);
        std::uint64_t carry = 0;
        for (std::size_t i = 0; i < t.size(); ++i) {
            const std::uint64_t cur = (static_cast<std::uint64_t>(t[i]) << rem) | carry;
            shifted[i + limb_shift] = static_cast<Limb>(cur);
            carry = cur >> 32;
        }
        shifted[t.size() + limb_shift] = static_cast<Limb>(carry);
        Trim(shifted);
        if (Cmp(a, shifted) >= 0) {
            if (a.size() < shifted.size()) {
                a.resize(shifted.size(), 0);
            }
            SubFrom(a, shifted);
            Trim(a);
        }
    }
    Trim(a);
    return a;
}

Big ModPow(Big base, const Big& exp, const Big& mod) {
    Big result{1};
    base = Mod(base, mod);
    for (std::size_t i = 0; i < exp.size(); ++i) {
        Limb e = exp[i];
        for (int b = 0; b < 32; ++b) {
            if (e & 1) {
                result = Mod(Mul(result, base), mod);
            }
            e >>= 1;
            base = Mod(Mul(base, base), mod);
        }
    }
    return result;
}

std::string XmlField(const std::string& xml, const std::string& tag) {
    const auto open = xml.find("<" + tag + ">");
    const auto close = xml.find("</" + tag + ">");
    if (open == std::string::npos || close == std::string::npos || close <= open) {
        return {};
    }
    return xml.substr(open + tag.size() + 2, close - (open + tag.size() + 2));
}

}  // namespace

Result<std::vector<std::uint8_t>> Base64Decode(std::string_view text) {
    std::string clean;
    clean.reserve(text.size());
    for (char c : text) {
        if (!std::isspace(static_cast<unsigned char>(c))) {
            clean.push_back(c);
        }
    }
    if (clean.size() % 4 != 0) {
        return Result<std::vector<std::uint8_t>>::fail("Invalid base64.");
    }
    std::vector<std::uint8_t> out;
    out.reserve(clean.size() / 4 * 3);
    for (std::size_t i = 0; i < clean.size(); i += 4) {
        int v[4];
        int pad = 0;
        for (int j = 0; j < 4; ++j) {
            if (clean[i + j] == '=') {
                v[j] = 0;
                ++pad;
            } else {
                v[j] = B64Value(clean[i + j]);
                if (v[j] < 0) {
                    return Result<std::vector<std::uint8_t>>::fail("Invalid base64.");
                }
            }
        }
        out.push_back(static_cast<std::uint8_t>((v[0] << 2) | (v[1] >> 4)));
        if (pad < 2) {
            out.push_back(static_cast<std::uint8_t>(((v[1] & 0xf) << 4) | (v[2] >> 2)));
        }
        if (pad < 1) {
            out.push_back(static_cast<std::uint8_t>(((v[2] & 0x3) << 6) | v[3]));
        }
    }
    return Result<std::vector<std::uint8_t>>::ok(std::move(out));
}

std::string Base64Encode(const std::uint8_t* data, std::size_t size) {
    static constexpr char kTable[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;
    out.reserve(((size + 2) / 3) * 4);
    for (std::size_t i = 0; i < size; i += 3) {
        const unsigned n = (data[i] << 16) | ((i + 1 < size ? data[i + 1] : 0) << 8) | (i + 2 < size ? data[i + 2] : 0);
        out.push_back(kTable[(n >> 18) & 63]);
        out.push_back(kTable[(n >> 12) & 63]);
        out.push_back(i + 1 < size ? kTable[(n >> 6) & 63] : '=');
        out.push_back(i + 2 < size ? kTable[n & 63] : '=');
    }
    return out;
}

Error AssertRsaPublicKeyXml(const std::string& xml) {
    const auto modulus = XmlField(xml, "Modulus");
    const auto exponent = XmlField(xml, "Exponent");
    if (modulus.empty() || exponent.empty()) {
        return Fail("A public RSA key of at least 3072 bits is required.");
    }
    auto mod = Base64Decode(modulus);
    if (!mod) {
        return Fail("A public RSA key of at least 3072 bits is required.");
    }
    if (mod.value.size() < 384) {
        return Fail("A public RSA key of at least 3072 bits is required.");
    }
    return Ok();
}

Error VerifyRsaSha256(const std::string& xml_public_key, const std::uint8_t* data, std::size_t size,
                      const std::uint8_t* signature, std::size_t signature_size) {
    auto modulus = Base64Decode(XmlField(xml_public_key, "Modulus"));
    auto exponent = Base64Decode(XmlField(xml_public_key, "Exponent"));
    if (!modulus || !exponent) {
        return Fail("Invalid policy signature.");
    }
    if (modulus.value.size() < 384 || signature_size != modulus.value.size()) {
        return Fail("Invalid policy signature.");
    }
    const auto n = FromBe(modulus.value.data(), modulus.value.size());
    const auto e = FromBe(exponent.value.data(), exponent.value.size());
    const auto s = FromBe(signature, signature_size);
    const auto m = ModPow(s, e, n);
    auto em = ToBe(m, modulus.value.size());
    const auto digest_hex = Sha256Hex(data, size);
    std::vector<std::uint8_t> digest(32);
    for (int i = 0; i < 32; ++i) {
        digest[static_cast<std::size_t>(i)] =
            static_cast<std::uint8_t>(std::stoi(digest_hex.substr(static_cast<std::size_t>(i) * 2, 2), nullptr, 16));
    }
    static const std::uint8_t kDigestInfoPrefix[] = {0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
                                                     0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20};
    if (em.size() < 3 + sizeof(kDigestInfoPrefix) + digest.size() || em[0] != 0x00 || em[1] != 0x01) {
        return Fail("Invalid policy signature.");
    }
    std::size_t i = 2;
    while (i < em.size() && em[i] == 0xff) {
        ++i;
    }
    if (i < 10 || i >= em.size() || em[i] != 0x00) {
        return Fail("Invalid policy signature.");
    }
    ++i;
    if (i + sizeof(kDigestInfoPrefix) + digest.size() != em.size()) {
        return Fail("Invalid policy signature.");
    }
    if (!std::equal(std::begin(kDigestInfoPrefix), std::end(kDigestInfoPrefix), em.begin() + static_cast<std::ptrdiff_t>(i))) {
        return Fail("Invalid policy signature.");
    }
    i += sizeof(kDigestInfoPrefix);
    if (!std::equal(digest.begin(), digest.end(), em.begin() + static_cast<std::ptrdiff_t>(i))) {
        return Fail("Invalid policy signature.");
    }
    return Ok();
}

Result<std::vector<std::uint8_t>> SignRsaSha256(std::string_view modulus_b64, std::string_view d_b64,
                                                const std::uint8_t* data, std::size_t size) {
    auto modulus = Base64Decode(modulus_b64);
    auto d = Base64Decode(d_b64);
    if (!modulus || !d) {
        return Result<std::vector<std::uint8_t>>::fail("Invalid RSA key.");
    }
    static const std::uint8_t kDigestInfoPrefix[] = {0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
                                                     0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20};
    const auto digest_hex = Sha256Hex(data, size);
    std::vector<std::uint8_t> em(modulus.value.size(), 0xff);
    em[0] = 0x00;
    em[1] = 0x01;
    const std::size_t digest_info = sizeof(kDigestInfoPrefix) + 32;
    const std::size_t ps_end = em.size() - digest_info - 1;
    em[ps_end] = 0x00;
    std::copy(std::begin(kDigestInfoPrefix), std::end(kDigestInfoPrefix), em.begin() + static_cast<std::ptrdiff_t>(ps_end + 1));
    for (int i = 0; i < 32; ++i) {
        em[em.size() - 32 + static_cast<std::size_t>(i)] =
            static_cast<std::uint8_t>(std::stoi(digest_hex.substr(static_cast<std::size_t>(i) * 2, 2), nullptr, 16));
    }
    const auto n = FromBe(modulus.value.data(), modulus.value.size());
    const auto exp = FromBe(d.value.data(), d.value.size());
    const auto m = FromBe(em.data(), em.size());
    const auto s = ModPow(m, exp, n);
    return Result<std::vector<std::uint8_t>>::ok(ToBe(s, modulus.value.size()));
}

}  // namespace st
