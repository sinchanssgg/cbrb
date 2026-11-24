#include "CRBB.h"
#include <random>

Define_Module(CRBB);

void CRBB::initialize() {
    id = par("id");
    n = par("n");
    t = par("t");
    c = par("c");
    senderId = par("senderId");
    d = t + c;
    k = d + 1;
    messageLen = par("messageLen");
    byzantine = par("byzantine");
    startTime = simTime().inUnit(SIMTIME_MS);

    // Initialize byzantine parameters
    byzantineMode = par("byzantineMode");
    variant = par("variant");
    equivocateFirst = par("equivocateFirst");
    helperTarget = par("helperTarget");
    floodTarget = par("floodTarget");
    floodCount = par("floodCount");

    if (id == senderId) {
        scheduleAt(simTime() + 0.001, new cMessage("start", 9000));
    }
}

void CRBB::scheduleTick(uint64_t sn) {
    // Reserved for future triggers.
    (void)sn;
}

void CRBB::handleMessage(cMessage *msg) {
    if (msg->getKind() == 9000) {
        std::vector<uint8_t> payload(messageLen, 0x11);
        initiate(id, 1, payload);
        delete msg;
        return;
    }
    if (msg->getKind() == CERT_KIND) {
        uint64_t sn = (uint64_t)msg->par("sn").longValue();
        auto key = std::make_pair(senderId, sn);
        auto &inst = instances[key];
        if (!inst.cert_adopted) {
            // In this model the controller is external; we simulate
            // the certificate as an event that sets a canonical set.
            for (int i = 0; i < k && i < n; ++i) inst.reader_set.insert(i);
            inst.cert_adopted = true;
            // Trigger own-share dispatch
            if (inst.reader_set.count(id)) {
                broadcast(MsgType::SUPPLY, sn, inst.own_share, id);
            } else {
                for (int r : inst.reader_set) sendMsg(MsgType::SUPPLY, r, sn, inst.own_share, id);
            }
            // Send COLLECT
            broadcast(MsgType::COLLECT, sn, {});
        }
        delete msg;
        return;
    }
    // Regular CRBB message: decode from cMessage par
    CRBBMessage m;
    m.type = (MsgType)msg->par("mtype").longValue();
    m.sender = msg->par("msender").longValue();
    m.mid_sender = msg->par("midSender").longValue();
    m.mid_sn = (uint64_t)msg->par("midSn").longValue();
    m.origin = msg->par("morigin").longValue();
    std::string p = msg->par("mpayload").stringValue() ? msg->par("mpayload").stringValue() : "";
    m.payload.assign(p.begin(), p.end());
    metrics[std::string("recv_") + std::to_string((int)m.type)]++;

    switch (m.type) {
    case MsgType::CARRY: onCarry(m.sender, m.mid_sn, m.payload); break;
    case MsgType::ECHO:  onEcho(m.sender, m.mid_sn, m.payload); break;
    case MsgType::READY: onReady(m.sender, m.mid_sn, m.payload); break;
    case MsgType::SHARE: onShare(m.sender, m.mid_sn, m.origin, m.payload); break;
    case MsgType::COLLECT: onCollect(m.sender, m.mid_sn); break;
    case MsgType::SUPPLY: onSupply(m.sender, m.mid_sn, m.origin, m.payload); break;
    }
    delete msg;
}

void CRBB::initiate(int sender, uint64_t sn, const std::vector<uint8_t> &payload) {
    if (byzantineMode == 3) {  // S3: equivocate VK across two halves
        auto &inst = instances[{sender, sn}];
        inst.own_share = payload;
        inst.vk = payload;
        for (int j = 0; j < n; ++j) {
            if (j == sender) continue;
            if (j < equivocateFirst) {
                sendMsg(MsgType::SHARE, j, sn, inst.own_share, j);
            } else {
                // Different VK tag for partition B
                std::vector<uint8_t> vkB = payload;
                vkB.push_back(0xFF); // differentiate
                sendMsg(MsgType::SHARE, j, sn, inst.own_share, j);
                auto *msg = new cMessage("crbb");
                msg->setKind(8000);
                msg->addPar("mtype") = (long)MsgType::CARRY;
                msg->addPar("msender") = (long)id;
                msg->addPar("midSender") = (long)senderId;
                msg->addPar("midSn") = (long)sn;
                msg->addPar("morigin") = -1;
                std::string s(vkB.begin(), vkB.end());
                msg->addPar("mpayload") = s.c_str();
                send(msg, "out", j);
            }
        }
        onCarry(sender, sn, inst.vk);
        return;
    }
    if (byzantineMode == 4) {  // S4: withhold beyond k-1
        auto &inst = instances[{sender, sn}];
        inst.own_share = payload;
        inst.vk = payload;
        int sent = 0;
        int need = k - 1;
        for (int j = 0; j < n && sent < need; ++j) {
            if (j == sender) continue;
            sendMsg(MsgType::SHARE, j, sn, inst.own_share, j);
            ++sent;
        }
        broadcast(MsgType::CARRY, sn, inst.vk);
        onCarry(sender, sn, inst.vk);
        return;
    }

    auto &inst = instances[{sender, sn}];
    inst.own_share = payload;  // stand-in for a real share
    inst.vk = payload;         // stand-in for the commitment vector
    // Send SHARE to every holder
    for (int j = 0; j < n; ++j) {
        if (j == sender) continue;
        sendMsg(MsgType::SHARE, j, sn, inst.own_share, j);
    }
    broadcast(MsgType::CARRY, sn, inst.vk);
    // Feed CARRY to self
    onCarry(sender, sn, inst.vk);
}

void CRBB::onCarry(int from, uint64_t sn, const std::vector<uint8_t> &vk) {
    auto &inst = instances[{senderId, sn}];
    if (inst.echo_sent) return;
    if (inst.vk_adopted && inst.vk != vk) return;
    inst.echo_sent = true;
    broadcast(MsgType::ECHO, sn, vk);
}

void CRBB::onEcho(int from, uint64_t sn, const std::vector<uint8_t> &vk) {
    auto &inst = instances[{senderId, sn}];
    if (inst.echo_recv.count(from)) return;
    inst.echo_recv[from] = vk;
    int count = 0;
    for (auto &p : inst.echo_recv) if (p.second == vk) count++;
    if (count >= n - t && !inst.ready_sent) {
        inst.vk_adopted = true;
        inst.vk = vk;
        inst.ready_sent = true;
        broadcast(MsgType::READY, sn, vk);
    }
}

void CRBB::onReady(int from, uint64_t sn, const std::vector<uint8_t> &vk) {
    auto &inst = instances[{senderId, sn}];
    if (inst.ready_recv.count(from)) return;
    inst.ready_recv[from] = vk;
    int count = 0;
    for (auto &p : inst.ready_recv) if (p.second == vk) count++;
    if (count >= t + 1 && !inst.ready_sent) {
        inst.vk_adopted = true;
        inst.vk = vk;
        inst.ready_sent = true;
        broadcast(MsgType::READY, sn, vk);
    }
    if (count >= n - t && !inst.vk_adopted) {
        inst.vk_adopted = true;
        inst.vk = vk;
    }
}

void CRBB::onShare(int from, uint64_t sn, int origin, const std::vector<uint8_t> &pair) {
    if (from != senderId || origin != id) return;
    auto &inst = instances[{senderId, sn}];
    if (inst.own_share.empty()) inst.own_share = pair;
}

void CRBB::onCollect(int from, uint64_t sn) {
    auto &inst = instances[{senderId, sn}];
    if (!inst.cert_adopted || !inst.reader_set.count(from)) return;

    if (byzantineMode == 1) {  // S1: withhold
        if (helperTarget == from) {
            // S4 helper path: send the real share to the target
            if (!inst.own_share.empty() && inst.vk_adopted) {
                sendMsg(MsgType::SUPPLY, from, sn, inst.own_share, id);
            }
        }
        return;
    }
    if (byzantineMode == 2) {  // S2: forged SUPPLY
        std::vector<uint8_t> forged(64, 0xAB);
        sendMsg(MsgType::SUPPLY, from, sn, forged, id);
        return;
    }
    if (byzantineMode == 6 && floodTarget == from) {  // S6: flood
        for (int i = 0; i < floodCount; ++i) {
            std::vector<uint8_t> bogus(64, (uint8_t)(i & 0xFF));
            sendMsg(MsgType::SUPPLY, from, sn, bogus, i % n);
        }
        return;
    }

    inst.requesters.insert(from);
    if (!inst.own_share.empty() && inst.vk_adopted) {
        sendMsg(MsgType::SUPPLY, from, sn, inst.own_share, id);
    }
}

void CRBB::onSupply(int from, uint64_t sn, int origin, const std::vector<uint8_t> &pair) {
    auto &inst = instances[{senderId, sn}];
    if (!inst.cert_adopted || !inst.reader_set.count(id)) return;
    if (inst.recon_done) return;
    bool from_reader = inst.reader_set.count(from) > 0;
    if (!from_reader && from != origin) return;
    if (inst.shares.count(origin)) return;
    inst.shares[origin] = pair;
    // Relay
    for (int r : inst.reader_set) {
        if (r == id || r == from) continue;
        sendMsg(MsgType::SUPPLY, r, sn, pair, origin);
    }
    tryReconstruct(sn);
}

void CRBB::tryReconstruct(uint64_t sn) {
    auto &inst = instances[{senderId, sn}];
    if (inst.recon_done) return;
    if ((int)inst.shares.size() + (inst.own_share.empty() ? 0 : 1) < k) return;
    inst.recon_done = true;
    inst.output = inst.own_share;  // stand-in for interpolation
    inst.shares.clear();
    inst.pending.clear();
    metrics["recon_done"]++;
    recordScalar("recon_done_ms", simTime().inUnit(SIMTIME_MS));
    recordScalar("shares_after_cleanup", (double)inst.shares.size());
}

void CRBB::sendMsg(MsgType type, int dst, uint64_t sn, const std::vector<uint8_t> &payload, int origin) {
    if (byzantine && (type == MsgType::SUPPLY || type == MsgType::SHARE)) {
        // Optionally drop or corrupt
        if (uniform(0, 1) < par("byzDropRate").doubleValue()) return;
    }
    auto *msg = new cMessage("crbb");
    msg->setKind(8000);
    msg->addPar("mtype") = (int)type;
    msg->addPar("msender") = id;
    msg->addPar("midSender") = senderId;
    msg->addPar("midSn") = (int)sn;
    msg->addPar("morigin") = origin;
    std::string s(payload.begin(), payload.end());
    msg->addPar("mpayload") = s.c_str();
    send(msg, "out", dst);
    metrics[std::string("sent_") + std::to_string((int)type)]++;
}

void CRBB::broadcast(MsgType type, uint64_t sn, const std::vector<uint8_t> &payload, int origin) {
    for (int dst = 0; dst < n; ++dst) {
        if (dst == id) continue;
        sendMsg(type, dst, sn, payload, origin);
    }
}

void CRBB::finish() {
    recordScalar("byzantineMode", byzantineMode);
    recordScalar("messages_sent",
                 (double)(metrics["sent_0"] + metrics["sent_1"] + metrics["sent_2"]));
    for (auto &p : metrics) recordScalar(p.first.c_str(), (double)p.second);
}