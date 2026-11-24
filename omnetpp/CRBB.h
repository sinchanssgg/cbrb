#ifndef __CRBB_H_
#define __CRBB_H_

#include <omnetpp.h>
#include <map>
#include <set>
#include <vector>
#include <string>
#include <cstdint>

    // Byzantine parameters
    int byzantineMode;    // 0=honest, 1=S1, 2=S2, 3=S3, 4=S4, 6=S6
    int variant;          // 0=CRBB, 1=CRBB-H
    int equivocateFirst;  // for S3: split point in the population
    int helperTarget;     // for S4: target reader for the helper
    int floodTarget;      // for S6: target reader
    int floodCount;       // for S6: number of forged SUPPLY messages
    std::set<int> excludedHolders;   // for S4: holders skipped by sender
    std::set<int> equivocateHalf;    // for S3: process ids in partition B

    std::set<int> contactedAsReader; // tracks reads already sent
    bool deliveryForbidden;          // set by byzantine S1 to reject deliveries

using namespace omnetpp;

enum class MsgType : uint8_t { CARRY = 0, ECHO = 1, READY = 2, SHARE = 3, COLLECT = 4, SUPPLY = 5 };

struct CRBBMessage {
    MsgType type;
    int sender;
    int mid_sender;
    uint64_t mid_sn;
    std::vector<uint8_t> payload;
    uint32_t origin;
};

struct InstanceState {
    bool echo_sent = false;
    bool ready_sent = false;
    bool vk_adopted = false;
    bool cert_adopted = false;
    bool recon_done = false;
    std::vector<uint8_t> vk;
    std::vector<uint8_t> own_share;
    std::set<int> reader_set;
    std::map<int, std::vector<uint8_t>> echo_recv;
    std::map<int, std::vector<uint8_t>> ready_recv;
    std::map<int, std::vector<uint8_t>> shares;
    std::map<std::pair<int,int>, std::vector<uint8_t>> pending;
    std::set<int> requesters;
    std::set<int> responded;
    std::vector<uint8_t> output;
};

class CRBB : public cSimpleModule {
  protected:
    int id, n, t, c, senderId;
    int k, d;
    int messageLen;
    uint64_t startTime;
    bool byzantine;
    std::map<std::pair<int,uint64_t>, InstanceState> instances;
    std::map<std::string, uint64_t> metrics;

    void initialize() override;
    void handleMessage(cMessage *msg) override;
    void finish() override;

    void initiate(int sender, uint64_t sn, const std::vector<uint8_t> &payload);
    void onCarry(int from, uint64_t sn, const std::vector<uint8_t> &vk);
    void onEcho(int from, uint64_t sn, const std::vector<uint8_t> &vk);
    void onReady(int from, uint64_t sn, const std::vector<uint8_t> &vk);
    void onShare(int from, uint64_t sn, int origin, const std::vector<uint8_t> &pair);
    void onCollect(int from, uint64_t sn);
    void onSupply(int from, uint64_t sn, int origin, const std::vector<uint8_t> &pair);

    void sendMsg(MsgType type, int dst, uint64_t sn, const std::vector<uint8_t> &payload, int origin = -1);
    void broadcast(MsgType type, uint64_t sn, const std::vector<uint8_t> &payload, int origin = -1);
    void scheduleCert(uint64_t sn);
    void tryReconstruct(uint64_t sn);
    void scheduleTick(uint64_t sn);

  public:
    static constexpr int TICK_KIND = 9001;
    static constexpr int CERT_KIND = 9002;
};

#endif