#include <cryptoTools/Common/Defines.h>
#include <cryptoTools/Crypto/PRNG.h>
#include <cryptoTools/Network/Channel.h>
#include <cryptoTools/Network/IOService.h>
#include <cryptoTools/Network/Session.h>
#include <libOTe/NChooseOne/Kkrt/KkrtNcoOtSender.h>

#include <array>
#include <iostream>

using namespace osuCrypto;

static block strTo128(std::string& s) {
  // assert s.length <= 16
  u64 h{0};
  u64 l{0};
  int len{s.length()};
  int b1 = len >= 8 ? 8 : len;
  int b2 = len > 8 ? (len - 8) : 0;
  for (int i{0}; i < b1; i++) {
    int c = s[i];
    u64 x = static_cast<u64>(c);
    int be = 8 * (7 - i);
    h += x << be;
  }
  for (int i{0}; i < b2; i++) {
    int c = s[8 + i];
    u64 x = static_cast<u64>(c);
    int be = 8 * (7 - i);
    l += x << be;
  }
  return toBlock(h, l);
}

int main(int argc, char** argv) {
  // initialize inputs
  constexpr int numChosenMsgs{4};
  std::array<std::string, numChosenMsgs> data{"Lelu", "Daniel", "John", "Rick"};
  std::array<block, numChosenMsgs> usernames;
  std::transform(data.begin(), data.end(), usernames.begin(), strTo128);

  // get up the networking
  IOService ios;
  Channel senderChl{
      Session(ios, "localhost:1212", SessionMode::Server).addChannel()};
  PRNG prng{sysRandomSeed()};

  KkrtNcoOtSender sender;

  // all Nco Ot extenders must have configure called first. This
  // determines a variety of parameters such as how many base OTs are
  // required.
  bool maliciousSecure = false;
  bool statSecParam = 40;
  bool inputBitCount = 128;
  sender.configure(maliciousSecure, statSecParam, inputBitCount);

  // generate new base OTs for the first extender.
  sender.genBaseOts(prng, senderChl);

  // populate this with the messages that you want to send.
  Matrix<block> sendMessages(1, usernames.size());
  for (int i{0}; i < numChosenMsgs; ++i) {
    sendMessages[0][i] = usernames[i];
  }

  // perform the OTs with the given messages.
  sender.sendChosen(sendMessages, prng, senderChl);
}