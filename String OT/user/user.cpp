#include <cryptoTools/Common/Defines.h>
#include <cryptoTools/Crypto/PRNG.h>
#include <cryptoTools/Network/Channel.h>
#include <cryptoTools/Network/IOService.h>
#include <cryptoTools/Network/Session.h>
#include <immintrin.h>
#include <libOTe/NChooseOne/Kkrt/KkrtNcoOtReceiver.h>
#include <stdalign.h>
#include <stdint.h>

#include <array>
#include <iostream>

using namespace osuCrypto;

static std::string blockToS(block& b) {
  std::string ret{""};
  alignas(16) uint8_t v[16];
  _mm_store_si128((__m128i*)v, b);
  // assume little endian
  for (int i{0}; i < 16; ++i) {
    char c = v[15 - i];
    if (!c) break;
    ret += c;
  }
  return ret;
}

int main(int argc, char** argv) {
  // setup parameters for the protocol
  constexpr int numChosenMsgs{4};
  constexpr int numOTs{1};

  std::cout << "Simple implementation of k (= " << numOTs
            << ") 1-out-of N (= " << numChosenMsgs << ") OTs for strings.\n\n";

  if (argc == 1) {
    std::cout << "You need to specify a choice.\nUsage: <program> <choice>\n";
    return -1;
  }

  // prepare vectors for messages and choices
  std::vector<block> recvMsgs(numOTs);
  std::vector<u64> choices(numOTs);
  choices[0] = atoi(argv[1]);

  // setup the networking (local)
  IOService ios;
  Channel recverChl{
      Session(ios, "localhost:1212", SessionMode::Client).addChannel()};

  // use the KKRT protocol for k 1-out-of-N OTs
  KkrtNcoOtReceiver recver;

  // OT configuration
  constexpr bool maliciousSecure{false};
  constexpr u64 statSecParam{40};
  constexpr u64 inputBitCount{128};
  recver.configure(maliciousSecure, statSecParam, inputBitCount);

  // generate new base OTs for the first extender
  PRNG prng{sysRandomSeed()};
  recver.genBaseOts(prng, recverChl);

  // the messages that were learned are written to recvMsgs.
  recver.receiveChosen(numChosenMsgs, recvMsgs, choices, prng, recverChl);

  // print the received string
  block ret = recvMsgs[0];
  std::cout << "Received msg for choice " << choices[0] << ": " << blockToS(ret)
            << '\n';

  return 0;
}
