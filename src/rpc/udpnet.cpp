// Copyright (c) 2017 Matt Corallo
// Unlike the rest of Bitcoin Core, this file is
// distributed under the Affero General Public License (AGPL v3)

#include <rpc/protocol.h>
#include <rpc/server.h>
#include <rpc/util.h>

#include <hash.h>
#include <netbase.h>
#include <udpapi.h>
#include <util/strencodings.h>

#include <univalue.h>

using namespace std;

RPCHelpMan getudppeerinfo()
{
    return RPCHelpMan{
        "getudppeerinfo",
        "Returns data about each connected UDP unicast peer as a json array of objects.\n",
        {},
        RPCResult{
            RPCResult::Type::ARR,
            "",
            "",
            {
                {RPCResult::Type::OBJ,
                 "",
                 "",
                 {
                     {RPCResult::Type::STR, "addr", "(host:port) The IP address and port of the peer"},
                     {RPCResult::Type::NUM, "group", "The group this peer belongs to"},
                     {RPCResult::Type::NUM, "lastrecv", "The time in seconds since epoch (Jan 1 1970 GMT) of the last receive"},
                     {RPCResult::Type::BOOL, "ultimatetrust", "Whether this peer, and all of its peers, are trusted"},
                     {RPCResult::Type::NUM, "min_recent_rtt", "The minimum RTT among recent pings (in ms)"},
                     {RPCResult::Type::NUM, "max_recent_rtt", "The maximum RTT among recent pings (in ms)"},
                     {RPCResult::Type::NUM, "avg_recent_rtt", "The average RTT among recent pings (in ms)"},
                 }},
            }},
        RPCExamples{HelpExampleCli("getudppeerinfo", "") + HelpExampleRpc("getudppeerinfo", "")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            vector<UDPConnectionStats> vstats;
            GetUDPConnectionList(vstats);

            UniValue ret(UniValue::VARR);

            for (const UDPConnectionStats& stats : vstats) {
                UniValue obj(UniValue::VOBJ);
                obj.pushKV("addr", stats.remote_addr.ToStringAddrPort());
                obj.pushKV("group", stats.group);
                obj.pushKV("lastrecv", stats.lastRecvTime);
                obj.pushKV("ultimatetrust", stats.fUltimatelyTrusted);

                double min = 1000000, max = 0, total = 0;

                for (double rtt : stats.last_pings) {
                    min = std::min(rtt, min);
                    max = std::max(rtt, max);
                    total += rtt;
                }

                obj.pushKV("min_recent_rtt", min);
                obj.pushKV("max_recent_rtt", max);
                obj.pushKV("avg_recent_rtt", stats.last_pings.size() == 0 ? 0 : total / stats.last_pings.size());

                ret.push_back(obj);
            }

            return ret;
        },
    };
}

RPCHelpMan addudpnode()
{
    return RPCHelpMan{
        "addudpnode",
        "Attempts add a node to the UDP addnode list.\n"
        "Or try a connection to a UDP node once.\n",
        {
            {"node", RPCArg::Type::STR, RPCArg::Optional::NO, "The node IP:port"},
            {"local_magic", RPCArg::Type::STR, RPCArg::Optional::NO, "Our magic secret value for this connection (should be a secure, random string)"},
            {"remote_magic", RPCArg::Type::STR, RPCArg::Optional::NO, "The node's magic secret value (should be a secure, random string)"},
            {"ultimately_trusted", RPCArg::Type::BOOL, RPCArg::Optional::NO, "Whether to trust this peer, and all of its trusted UDP peers, recursively"},
            {"command", RPCArg::Type::STR, RPCArg::Optional::NO, "'add' to add a persistent connection or 'onetry' to try a connection to the node once"},
            {"group", RPCArg::Type::NUM, RPCArg::Default{0}, "'add' to add a persistent connection or 'onetry' to try a connection to the node once"},
            {"type", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "May be one of 'bidirectional', 'inbound_only' or 'I_certify_remote_is_listening_and_not_a_DoS_target_outbound_only'."},
        },
        RPCResult{RPCResult::Type::NONE, "", ""},
        RPCExamples{
            HelpExampleCli("addudpnode", "\"192.168.0.6:8333\" \"PA$$WORD\" \"THEIR_PA$$\" false \"onetry\"") +
            HelpExampleRpc("addudpnode", "\"192.168.0.6:8333\" \"PA$$WORD\" \"THEIR_PA$$\" false \"onetry\"")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            string strNode = request.params[0].get_str();

            string strCommand;
            if (request.params.size() >= 5)
                strCommand = request.params[4].get_str();

            if (strCommand != "onetry" && strCommand != "add")
                throw JSONRPCError(RPC_INVALID_PARAMS, "Parameter 'command' must be 'onetry' or 'add'");

            const std::optional<CService> addr{Lookup(strNode.c_str(), -1, /*fAllowLookup=*/true)};
            if (!addr.has_value() || !addr->IsValid())
                throw JSONRPCError(RPC_INVALID_PARAMS, "Error: Failed to lookup node, address not valid or port missing.");

            string local_pass = request.params[1].get_str();
            uint64_t local_magic = Hash(local_pass).GetUint64(0);
            string remote_pass = request.params[2].get_str();
            uint64_t remote_magic = Hash(remote_pass).GetUint64(0);

            bool fTrust = request.params[3].get_bool();

            size_t group = 0;
            if (request.params.size() >= 6)
                group = request.params[5].getInt<int64_t>();
            if (group > GetUDPInboundPorts().size())
                throw JSONRPCError(RPC_INVALID_PARAMS, "Error: Group out of range or UDP port not bound");

            UDPConnectionType connection_type = UDP_CONNECTION_TYPE_NORMAL;
            if (request.params.size() >= 7) {
                if (request.params[6].get_str() == "inbound_only")
                    connection_type = UDP_CONNECTION_TYPE_INBOUND_ONLY;
                else if (request.params[6].get_str() == "I_certify_remote_is_listening_and_not_a_DoS_target_oubound_only")
                    connection_type = UDP_CONNECTION_TYPE_OUTBOUND_ONLY;
                else if (request.params[6].get_str() != "bidirectional")
                    throw JSONRPCError(RPC_INVALID_PARAMS, "Bad argument for connection type");
            }

            if (strCommand == "onetry")
                OpenUDPConnectionTo(addr.value(), local_magic, remote_magic, fTrust, connection_type, group);
            else if (strCommand == "add")
                OpenPersistentUDPConnectionTo(addr.value(), local_magic, remote_magic, fTrust, connection_type, group);

            return UniValue::VNULL;
        },
    };
}

RPCHelpMan disconnectudpnode()
{
    return RPCHelpMan{
        "disconnectudpnode",
        "Disconnects a connected UDP node.\n",
        {
            {"node", RPCArg::Type::STR, RPCArg::Optional::NO, "The node IP:port"},
        },
        RPCResults{},
        RPCExamples{
            HelpExampleCli("disconnectudpnode", "\"192.168.0.6:8333\"") +
            HelpExampleRpc("disconnectudpnode", "\"192.168.0.6:8333\"")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            string strNode = request.params[0].get_str();

            const std::optional<CService> addr{Lookup(strNode.c_str(), -1, true)};
            if (!addr.has_value() || !addr->IsValid())
                throw JSONRPCError(RPC_INVALID_PARAMS, "Error: Failed to lookup node, address not valid or port missing.");

            CloseUDPConnectionTo(addr.value());

            return NullUniValue;
        },
    };
}

void RegisterUDPNetRPCCommands(CRPCTable& t)
{
    // clang-format off
    static const CRPCCommand commands[] =
    { //  category              actor (function)
      //  --------------------- ------------------------
        {"udpnetwork",          &getudppeerinfo          },
        {"udpnetwork",          &addudpnode              },
        {"udpnetwork",          &disconnectudpnode       }
    };
    // clang-format on
    for (const auto& c : commands) {
        t.appendCommand(c.name, &c);
    }
}
