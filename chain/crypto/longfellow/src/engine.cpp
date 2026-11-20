// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// The range statement on Longfellow ZK: its circuit, built from the library's
// own gadgets, and the prover and verifier around it.
//
// The circuit, over GF(2^128), with one copy:
//   - Public inputs, in order: the constant 1; C's 256 bits, byte 0 first and
//     each byte least significant bit first; low's 64 bits, then high's 64
//     bits, each least significant bit first.
//   - Private inputs: the salt's 256 bits and the value's 64 bits, in the same
//     order; then the witness of one SHA-256 compression (48 message-schedule
//     words, then 64 pairs of round values e and a), packed four bits to an
//     element (BitPlucker<4>).
//   - Constraints: the compression of the padded block
//     "Kanhe range v1" || salt || BE64(value) || 0x80 || 0^7 || BE64(432),
//     from SHA-256's initial hash value, gives C
//     (FlatSHA256Circuit::assert_transform_block); low <= value and
//     value <= high (Logic::vleq). The block's other bytes are constants of
//     the circuit, so only the salt and the value are free.
// The order in which the gates are made is part of the circuit, and so of its
// id: the id is pinned, and a circuit built otherwise, by this code or by
// another version of the library's compiler, is refused.
//
// A circuit can also be loaded from its serialized form (load), which a
// build with KANHE_RANGE_LOAD_ONLY must do before any proof: it leaves the
// circuit's compiler out (the browser verifier, where loading is faster).

#include "engine.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <mutex>
#include <span>
#include <vector>

#include <openssl/evp.h>

#include <kanhe/crypto/longfellow.hpp>

#include "arrays/dense.h"
#if !defined(KANHE_RANGE_LOAD_ONLY)
#include "circuits/compiler/compiler.h"
#include "circuits/logic/bit_plucker.h"
#include "circuits/logic/compiler_backend.h"
#include "circuits/logic/logic.h"
#include "circuits/sha/flatsha256_circuit.h"
#endif
#include "circuits/logic/bit_plucker_encoder.h"
#include "circuits/sha/flatsha256_witness.h"
#include "gf2k/gf2_128.h"
#include "gf2k/lch14_reed_solomon.h"
#include "proto/circuit_io.h"
#include "proto/circuit_reader.h"
#include "proto/circuit_writer.h"
#include "random/random.h"
#include "random/secure_random_engine.h"
#include "random/transcript.h"
#include "sumcheck/circuit.h"
#include "sumcheck/circuit_id.h"
#include "util/log.h"
#include "util/readbuffer.h"
#include "zk/zk_proof.h"
#include "zk/zk_prover.h"
#include "zk/zk_verifier.h"

namespace kanhe::crypto::longfellow::engine {

const Block pinned_circuit_id = {0xfc, 0x72, 0x7b, 0x67, 0x26, 0xbd, 0x4b, 0xfe, 0x80, 0xb6, 0x5d,
                                 0x04, 0x4c, 0xdb, 0x4d, 0x39, 0x3f, 0xcc, 0x68, 0x8b, 0x5a, 0xad,
                                 0x0a, 0xb4, 0xde, 0xd3, 0xa9, 0x61, 0x94, 0x59, 0x48, 0x0a};

namespace {

using Field = proofs::GF2_128<>;
using Circuit = proofs::Circuit<Field>;
using RSFactory = proofs::LCH14ReedSolomonFactory<Field>;

// The parameters of Longfellow's proofs version 7, as its own circuits use.
constexpr std::size_t ligero_rate = 7;
constexpr std::size_t ligero_queries = 132;
constexpr std::size_t transcript_version = 7;
// Bits per packed element of the SHA-256 witness.
constexpr std::size_t plucker_bits = 4;

constexpr std::size_t value_bits = 64;
constexpr std::size_t prefix_size = 14;
constexpr std::size_t message_size = prefix_size + 32 + 8;
constexpr std::size_t public_inputs = 1 + 256 + 2 * value_bits;
static_assert(range_commitment_prefix.size() == prefix_size);
static_assert(message_size == 54, "one SHA-256 block, with its padding");

constexpr std::array<std::uint32_t, 8> sha256_iv = {0x6a09e667U, 0xbb67ae85U, 0x3c6ef372U,
                                                    0xa54ff53aU, 0x510e527fU, 0x9b05688cU,
                                                    0x1f83d9abU, 0x5be0cd19U};

#if !defined(KANHE_RANGE_LOAD_ONLY)
std::unique_ptr<Circuit> build_circuit(const Field& F) {
    using Backend = proofs::CompilerBackend<Field>;
    using Logic = proofs::Logic<Field, Backend>;
    using v8 = Logic::v8;
    using v32 = Logic::v32;
    using Bits = Logic::bitvec<value_bits>;
    using Sha = proofs::FlatSHA256Circuit<Logic, proofs::BitPlucker<Logic, plucker_bits>>;
    using packed_v32 = Sha::packed_v32;

    proofs::QuadCircuit<Field> Q(F);
    const Backend backend(&Q);
    const Logic L(&backend, F);
    Sha sha(L);

    // Public inputs. vinput asserts that each wire is a bit.
    std::vector<v8> C(32);
    for (auto& byte : C) {
        byte = L.vinput<8>();
    }
    Bits low;
    Bits high;
    low = L.vinput<value_bits>();
    high = L.vinput<value_bits>();

    // Private inputs, all in the subfield (bits and packed bits).
    Q.private_input();
    std::vector<v8> salt(32);
    for (auto& byte : salt) {
        byte = L.vinput<8>();
    }
    const Bits value = L.vinput<value_bits>();
    std::vector<packed_v32> packed_w(48);
    std::vector<packed_v32> packed_e(64);
    std::vector<packed_v32> packed_a(64);
    for (auto& word : packed_w) {
        word = Sha::packed_input(L);
    }
    for (std::size_t k = 0; k < 64; ++k) {
        packed_e[k] = Sha::packed_input(L);
        packed_a[k] = Sha::packed_input(L);
    }
    Q.begin_full_field(); // no private inputs in the full field follow

    // The padded block: constant but for the salt and the value.
    std::vector<v8> m(64);
    for (std::size_t i = 0; i < prefix_size; ++i) {
        m[i] = L.vbit8(static_cast<std::uint8_t>(range_commitment_prefix[i]));
    }
    for (std::size_t i = 0; i < 32; ++i) {
        m[prefix_size + i] = v8(salt[i]);
    }
    for (std::size_t j = 0; j < 8; ++j) {
        const std::size_t byte = 7 - j; // big-endian: m[46] holds the top byte
        for (std::size_t k = 0; k < 8; ++k) {
            m[prefix_size + 32 + j][k] = value[8 * byte + k];
        }
    }
    m[54] = L.vbit8(0x80);
    for (std::size_t i = 55; i < 62; ++i) {
        m[i] = L.vbit8(0);
    }
    m[62] = L.vbit8(0x01); // the message's length in bits, 432 = 0x01b0
    m[63] = L.vbit8(0xb0);

    // Big-endian words; vappend's first argument holds the low bits.
    std::vector<v32> in(16);
    std::vector<v32> h0(8);
    std::vector<v32> h1(8);
    std::vector<v32> w(48);
    std::vector<v32> e(64);
    std::vector<v32> a(64);
    for (std::size_t i = 0; i < 16; ++i) {
        in[i] =
            L.vappend(L.vappend(m[4 * i + 3], m[4 * i + 2]), L.vappend(m[4 * i + 1], m[4 * i + 0]));
    }
    for (std::size_t i = 0; i < 8; ++i) {
        h0[i] = L.vbit32(sha256_iv[i]);
        h1[i] =
            L.vappend(L.vappend(C[4 * i + 3], C[4 * i + 2]), L.vappend(C[4 * i + 1], C[4 * i + 0]));
    }
    for (std::size_t k = 0; k < 48; ++k) {
        w[k] = sha.bp_.unpack_v32(packed_w[k]);
    }
    for (std::size_t k = 0; k < 64; ++k) {
        e[k] = sha.bp_.unpack_v32(packed_e[k]);
        a[k] = sha.bp_.unpack_v32(packed_a[k]);
    }
    // One compression from the initial hash value gives C.
    sha.assert_transform_block(in.data(), h0.data(), w.data(), e.data(), a.data(), h1.data());

    // The range.
    L.assert1(L.vleq(low, value));
    L.assert1(L.vleq(value, high));

    return Q.mkcircuit(/*nc=*/1);
}
#endif

bool has_pinned_id(const std::uint8_t* id) {
    return std::equal(pinned_circuit_id.begin(), pinned_circuit_id.end(), id);
}

/// The circuit in use and its field.
struct Engine {
    const Field field;
    std::unique_ptr<const Circuit> circuit;
};

/// The engine, once a circuit has been built or loaded: set once, then
/// neither replaced nor changed until the process ends, so that a pointer to
/// it stays valid without the lock.
std::mutex engine_mutex;
std::unique_ptr<const Engine> current_engine;

void quiet() {
    // The library logs its steps to standard error; only its errors here.
    static std::once_flag once;
    std::call_once(once, [] { proofs::set_log_level(proofs::ERROR); });
}

#if defined(KANHE_RANGE_LOAD_ONLY)
std::unexpected<Error> not_ready() {
    return fail(Errc::crypto_failure, "the range circuit has not been loaded");
}
#else
bool build_tried = false;

std::unexpected<Error> not_ready() {
    return fail(Errc::crypto_failure, "the range circuit built does not match its pinned id");
}

/// The circuit built from code, if it is the pinned one: the compiler's id,
/// and the same computed again from the circuit.
std::unique_ptr<const Engine> built() {
    quiet();
    auto engine = std::make_unique<Engine>();
    auto circuit = build_circuit(engine->field);
    if (circuit == nullptr) {
        return nullptr;
    }
    Block recomputed{};
    proofs::circuit_id(recomputed.data(), *circuit, engine->field);
    if (circuit->npub_in != public_inputs || !has_pinned_id(circuit->id) ||
        !has_pinned_id(recomputed.data())) {
        return nullptr;
    }
    engine->circuit = std::move(circuit);
    return engine;
}
#endif

/// The engine: the circuit loaded, or else built the first time it is
/// needed (once per process, even if it does not match).
Result<const Engine*> engine() {
    const std::lock_guard lock(engine_mutex);
#if !defined(KANHE_RANGE_LOAD_ONLY)
    if (current_engine == nullptr && !build_tried) {
        build_tried = true;
        current_engine = built();
    }
#endif
    if (current_engine == nullptr) {
        return not_ready();
    }
    return current_engine.get();
}

/// The prover's randomness from a seed: the AES-256-CTR keystream under it,
/// with a zero IV. A failure leaves zeros and is reported by ok().
class SeededRandom final : public proofs::RandomEngine {
public:
    explicit SeededRandom(const Block& seed) : ctx_(EVP_CIPHER_CTX_new()) {
        static constexpr std::array<std::uint8_t, 16> iv{};
        ok_ = ctx_ != nullptr &&
              EVP_EncryptInit_ex(ctx_, EVP_aes_256_ctr(), nullptr, seed.data(), iv.data()) == 1;
    }
    ~SeededRandom() override { EVP_CIPHER_CTX_free(ctx_); }
    SeededRandom(const SeededRandom&) = delete;
    SeededRandom& operator=(const SeededRandom&) = delete;
    SeededRandom(SeededRandom&&) = delete;
    SeededRandom& operator=(SeededRandom&&) = delete;

    void bytes(std::uint8_t* buf, std::size_t n) override {
        if (n == 0) {
            return;
        }
        std::fill_n(buf, n, std::uint8_t{0});
        // The keystream is the encryption of zeros, in place.
        while (n > 0 && ok_) {
            const std::size_t chunk = std::min<std::size_t>(n, std::size_t{1} << 20);
            int written = 0;
            ok_ = EVP_EncryptUpdate(ctx_, buf, &written, buf, static_cast<int>(chunk)) == 1 &&
                  static_cast<std::size_t>(written) == chunk;
            buf += chunk;
            n -= chunk;
        }
    }

    [[nodiscard]] bool ok() const noexcept { return ok_; }

private:
    EVP_CIPHER_CTX* ctx_;
    bool ok_ = false;
};

/// The public inputs: the constant 1, then C, low, and high.
void fill_public(proofs::DenseFiller<Field>& filler, const Field& F, const Statement& statement) {
    const auto bit = [&](std::uint64_t b) {
        return b != 0 ? F.one() : F.zero();
    };
    filler.push_back(F.one());
    for (const std::uint8_t byte : statement.commitment) {
        for (unsigned k = 0; k < 8; ++k) {
            filler.push_back(bit((std::uint64_t{byte} >> k) & 1U));
        }
    }
    for (unsigned k = 0; k < value_bits; ++k) {
        filler.push_back(bit((statement.low >> k) & 1U));
    }
    for (unsigned k = 0; k < value_bits; ++k) {
        filler.push_back(bit((statement.high >> k) & 1U));
    }
}

template <class T>
void wipe(std::vector<T>& values) {
    secure_wipe(
        std::span(reinterpret_cast<std::uint8_t*>(values.data()), values.size() * sizeof(T)));
}

template <class T, std::size_t N>
void wipe(std::array<T, N>& values) {
    secure_wipe(std::span(reinterpret_cast<std::uint8_t*>(values.data()), N * sizeof(T)));
}

} // namespace

Status ready() {
    const auto e = engine();
    if (!e) {
        return std::unexpected(e.error());
    }
    return {};
}

Status load(ByteView serialized) {
    quiet();
    auto loaded = std::make_unique<Engine>();
    proofs::ReadBuffer buffer(serialized.data(), serialized.size());
    proofs::CircuitReader<Field> reader(loaded->field, proofs::GF2_128_ID);
    // The reader computes the id again from the terms it read, and refuses
    // a circuit whose terms do not give the id it carries.
    auto circuit = reader.from_bytes(buffer, /*enforce_circuit_id=*/true);
    if (circuit == nullptr) {
        return fail(Errc::malformed,
                    "the range circuit does not parse, or does not have the id it carries");
    }
    if (buffer.remaining() != 0) {
        return fail(Errc::malformed, "the range circuit has bytes left over");
    }
    if (circuit->npub_in != public_inputs || !has_pinned_id(circuit->id)) {
        return fail(Errc::crypto_failure, "the range circuit loaded does not match its pinned id");
    }
    loaded->circuit = std::move(circuit);
    const std::lock_guard lock(engine_mutex);
    if (current_engine == nullptr) {
        current_engine = std::move(loaded);
    }
    return {};
}

Result<Bytes> circuit_bytes() {
    const auto engine_in_use = engine();
    if (!engine_in_use) {
        return std::unexpected(engine_in_use.error());
    }
    const Engine& e = **engine_in_use;
    proofs::CircuitWriter<Field> writer(e.field, proofs::GF2_128_ID);
    Bytes bytes;
    writer.to_bytes(*e.circuit, bytes);
    // Read back, with the id computed again from what was read.
    proofs::ReadBuffer buffer(bytes);
    proofs::CircuitReader<Field> reader(e.field, proofs::GF2_128_ID);
    const auto back = reader.from_bytes(buffer, /*enforce_circuit_id=*/true);
    if (back == nullptr || buffer.remaining() != 0 || !has_pinned_id(back->id)) {
        return fail(Errc::crypto_failure,
                    "the serialized range circuit does not read back to its pinned id");
    }
    return bytes;
}

Result<Bytes> prove(const Statement& statement, const Block& salt, std::uint64_t value,
                    ByteView transcript, const Block* seed) {
    const auto e = engine();
    if (!e) {
        return std::unexpected(e.error());
    }
    const Field& F = (*e)->field;
    const Circuit& c = *(*e)->circuit;
    const auto bit = [&](std::uint64_t b) {
        return b != 0 ? F.one() : F.zero();
    };

    proofs::Dense<Field> inputs(1, c.ninputs);
    proofs::DenseFiller<Field> filler(inputs);
    fill_public(filler, F, statement);
    for (const std::uint8_t byte : salt) {
        for (unsigned k = 0; k < 8; ++k) {
            filler.push_back(bit((std::uint64_t{byte} >> k) & 1U));
        }
    }
    for (unsigned k = 0; k < value_bits; ++k) {
        filler.push_back(bit((value >> k) & 1U));
    }

    // The SHA-256 witness, from the padded block.
    std::array<std::uint8_t, 64> block{};
    std::copy(range_commitment_prefix.begin(), range_commitment_prefix.end(), block.begin());
    std::copy(salt.begin(), salt.end(), block.begin() + prefix_size);
    for (unsigned j = 0; j < 8; ++j) {
        block[prefix_size + 32 + j] = static_cast<std::uint8_t>(value >> (56U - 8U * j));
    }
    block[54] = 0x80;
    block[62] = 0x01;
    block[63] = 0xb0;
    std::array<std::uint32_t, 16> in{};
    for (std::size_t i = 0; i < 16; ++i) {
        in[i] = (std::uint32_t{block[4 * i]} << 24U) | (std::uint32_t{block[4 * i + 1]} << 16U) |
                (std::uint32_t{block[4 * i + 2]} << 8U) | std::uint32_t{block[4 * i + 3]};
    }
    std::array<std::uint32_t, 48> w{};
    std::array<std::uint32_t, 64> rounds_e{};
    std::array<std::uint32_t, 64> rounds_a{};
    std::array<std::uint32_t, 8> h1{};
    proofs::FlatSHA256Witness::transform_and_witness_block(
        in.data(), sha256_iv.data(), w.data(), rounds_e.data(), rounds_a.data(), h1.data());
    proofs::BitPluckerEncoder<Field, plucker_bits> encoder(F);
    for (const std::uint32_t word : w) {
        filler.push_back(encoder.mkpacked_v32(word));
    }
    for (std::size_t k = 0; k < 64; ++k) {
        filler.push_back(encoder.mkpacked_v32(rounds_e[k]));
        filler.push_back(encoder.mkpacked_v32(rounds_a[k]));
    }

    Bytes out;
    bool proved = false;
    if (filler.size() == c.ninputs) {
        const RSFactory rsf(F);
        proofs::ZkProof<Field> zk(c, ligero_rate, ligero_queries);
        proofs::Transcript t(transcript.data(), transcript.size(), transcript_version);
        proofs::ZkProver<Field, RSFactory> prover(c, F, rsf);
        if (seed != nullptr) {
            SeededRandom rng(*seed);
            prover.commit(zk, inputs, t, rng);
            proved = rng.ok() && prover.prove(zk, inputs, t);
        } else {
            proofs::SecureRandomEngine rng;
            prover.commit(zk, inputs, t, rng);
            proved = prover.prove(zk, inputs, t);
        }
        if (proved) {
            zk.write(out, F);
        }
    }
    // This code's copies of the secret (the library frees its own unwiped).
    wipe(inputs.v_);
    wipe(block);
    wipe(in);
    wipe(w);
    wipe(rounds_e);
    wipe(rounds_a);
    if (!proved) {
        return fail(Errc::crypto_failure, "the range prover failed");
    }
    return out;
}

Status verify(const Statement& statement, ByteView transcript, ByteView proof) {
    const auto e = engine();
    if (!e) {
        return std::unexpected(e.error());
    }
    const Field& F = (*e)->field;
    const Circuit& c = *(*e)->circuit;

    proofs::ZkProof<Field> zk(c, ligero_rate, ligero_queries);
    proofs::ReadBuffer buffer(proof.data(), proof.size());
    if (!zk.read(buffer, F)) {
        return fail(Errc::malformed, "the range proof does not parse");
    }
    if (buffer.remaining() != 0) {
        return fail(Errc::malformed, "the range proof has bytes left over");
    }

    proofs::Dense<Field> inputs(1, c.npub_in);
    proofs::DenseFiller<Field> filler(inputs);
    fill_public(filler, F, statement);

    const RSFactory rsf(F);
    const proofs::ZkVerifier<Field, RSFactory> verifier(c, rsf, ligero_rate, ligero_queries, F);
    proofs::Transcript t(transcript.data(), transcript.size(), transcript_version);
    verifier.recv_commitment(zk, t);
    if (!verifier.verify(zk, inputs, t)) {
        return fail(Errc::verification_failed, "the range proof does not verify");
    }
    return {};
}

} // namespace kanhe::crypto::longfellow::engine
