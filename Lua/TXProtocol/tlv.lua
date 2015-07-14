--[=======[
-------- -------- -------- --------
             TX TLV
-------- -------- -------- --------

    TXP.TLVBuilder                      --TLV数据包构建函数组
    TXP.TLVAnalyzer                     --TLV数据包解析函数组
    TXP.TLVSpy                          --TLV数据包分解函数组
    TXP.TLVName                         --TLV名称组
]=======]
TXP.TLVBuilder = {};
TXP.TLVAnalyzer = {};
TXP.TLVSpy = {};
TXP.TLVName = {};
--[=======[
    string    TXP.CreateTLVSubVerName   ( int tag );
        --指定TLV的tag，生成"tlv%04Xsubver"，用于查询可能存在的tlv子版本号
]=======]
function TXP.CreateTLVSubVerName( tag )
    return "tlv" .. string.format("%04X", tag) .. "subver";
end
--[=======[
-------- -------- -------- --------
           TLV脚本组
-------- -------- -------- --------

    0004                                NonUinAccount
    0005                                Uin
    0006                                TGTGT
    0007                                TGT
    0008                                TimeZone
    000A                                ErrorInfo
    000C                                PingRedirect
    000D
    0014
    0015                                ComputerGuid
    0017                                ClientInfo
    0018                                Ping
    001A                                GTKeyTGTGTCryptedData
    001E                                GTKey_TGTGT
    001F                                DeviceID
    002D                                LocalIP
    002F
    0032                                QdData
    0036                                LoginReason
    0100                                ErrorCode
    0102                                Official
    0103                                SID
    0105                                m_vec0x12c
    0107                                TicketInfo
    0108                                AccountBasicInfo
    0109                                0xddReply
    010B                                QDLoginFlag
    010C
    010D                                SigLastLoginInfo
    010E
    0110                                SigPic
    0112                                SigIP2
    0114                                DHParams
    0115                                PacketMd5
    0309                                Ping_Strategy
    030F                                ComputerName
    0310                                ServerAddress
    0312                                Misc_Flag
    0313                                GUID_Ex

]=======]
require "TXProtocol/TLV/0004";
require "TXProtocol/TLV/0005";
require "TXProtocol/TLV/0006";
require "TXProtocol/TLV/0007";
require "TXProtocol/TLV/0008";
require "TXProtocol/TLV/000A";
require "TXProtocol/TLV/000C";
require "TXProtocol/TLV/000D";
require "TXProtocol/TLV/0014";
require "TXProtocol/TLV/0015";
require "TXProtocol/TLV/0017";
require "TXProtocol/TLV/0018";
require "TXProtocol/TLV/001A";
require "TXProtocol/TLV/001E";
require "TXProtocol/TLV/001F";
require "TXProtocol/TLV/002D";
require "TXProtocol/TLV/002F";
require "TXProtocol/TLV/0032";
require "TXProtocol/TLV/0036";
require "TXProtocol/TLV/0100";
require "TXProtocol/TLV/0102";
require "TXProtocol/TLV/0103";
require "TXProtocol/TLV/0105";
require "TXProtocol/TLV/0107";
require "TXProtocol/TLV/0108";
require "TXProtocol/TLV/0109";
require "TXProtocol/TLV/010B";
require "TXProtocol/TLV/010C";
require "TXProtocol/TLV/010D";
require "TXProtocol/TLV/010E";
require "TXProtocol/TLV/0110";
require "TXProtocol/TLV/0112";
require "TXProtocol/TLV/0114";
require "TXProtocol/TLV/0115";
require "TXProtocol/TLV/0309";
require "TXProtocol/TLV/030F";
require "TXProtocol/TLV/0310";
require "TXProtocol/TLV/0312";
require "TXProtocol/TLV/0313";