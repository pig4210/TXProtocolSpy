--[=======[
-------- -------- -------- --------
           TX Packet
-------- -------- -------- --------

    TXP.PacketName                      --数据包名
    TXP.PacketBuilder                   --数据包构建函数组
    TXP.PacketAnalyzer                  --数据包解析函数组
    TXP.PacketResultName                --数据包对应结果命名组
    TXP.PacketSendSpy                   --发包解析函数组
    TXP.PacketRecvSpy                   --收包解析函数组

    TXP.Packet_PreFix                   --数据包前缀 "\x02"
    TXP.Packet_SufFix                   --数据包后缀 "\x03"
    TXP.TEAN_Key_Size                   --TEAN Key大小 0x10
]=======]
TXP.PacketName              = {};
TXP.PacketBuilder           = {};
TXP.PacketAnalyzer          = {};
TXP.PacketResultName        = {};
TXP.PacketSendSpy           = {};
TXP.PacketRecvSpy           = {};

TXP.Packet_PreFix           = "\x02";
TXP.Packet_SufFix           = "\x03";
TXP.TEAN_Key_Size           = 0x10;
--[=======[
    string    TXP.CreateKeyName         ( int cscmd, int csseq );
        --指定指令号、指令序号，生成"%04X-%04X"这样的字符串
]=======]
function TXP.CreateKeyName( cscmd, csseq )
  return string.format("%04X-%04X", cscmd, csseq);
end
--[=======[
    stirng    TXP.CreateSpyKeyName      ( int cscmd, int csseq );
        --指定指令号、指令序号，生成"Spy%04X-%04X"这样的字符串
]=======]
function TXP.CreateSpyKeyName( cscmd, csseq )
  return string.format("Spy%04X-%04X", cscmd, csseq);
end
--[=======[
    string    TXP.PacketBuilderFix      ( TXData td, string data );
        --指定数据环境，已经组织好的封包
          前缀添加Packet_PreFix、cMainVer、cSubVer
          后缀添加Packet_SufFix
          若使用tcp模式通讯，自动添加数据头
          data允许为string或txline
]=======]
function TXP.PacketBuilderFix( td, data )
  if type(data) == "table" then
    data = data.line;
  end
  local packet = txline:new();
  packet:sa(TXP.Packet_PreFix);
  packet:sb(td.cMainVer);
  packet:sb(td.cSubVer);
  packet:sa(data);
  packet:sa(TXP.Packet_SufFix);
  local tcpsize = "";
  if td.istcp then
    local buf = txline.new();
    buf:sh(#packet.line);
    tcpsize = buf.line;
  end
  return tcpsize .. packet.line;
end
--[=======[
    bool      TXP.IsTXPacket            ( TXData data | string data );
        --检测指定封包是否TXProtocol封包，data允许为string或txline
]=======]
function TXP.IsTXPacket( data )
  if type(data) == "table" then
    data = data.line;
  end
  return
  (data:sub(1, #TXP.Packet_PreFix) == TXP.Packet_PreFix) and
  (data:sub(-1, 0-#TXP.Packet_SufFix) == TXP.Packet_SufFix);
end
--[=======[
    string    TXP.PacketAnalyzerFix            ( TXData data | string data );
        --检测指定封包是否TXProtocol封包，如果是，返回去除前后缀的数据
          data允许为string或txline
]=======]
function TXP.PacketAnalyzerFix( data )
  if type(data) == "table" then
    data = data.line;
  end
  if not TXP.IsTXPacket(data) then
    return "";
  end
  return data:sub(1 + #TXP.Packet_PreFix, -1 - #TXP.Packet_SufFix);
end
--[=======[
    string, string TXP.PacketSpy(
        TXData  td,
        string  ip,
        string  data,
        bool    send_or_recv
        );
      --指定数据环境，IP信息，封包，发送或接收，格式化封包
      --返回简要信息、详细封包格式化信息
]=======]
function TXP.PacketSpy( td, ip, data, send_or_recv )
  local nf,nff;
  if send_or_recv then
    nf = "●";
    nff = nf .. " SEND " .. nf;
  else
    nf = "○";
    nff = nf .. " RECV " .. nf;
  end
  if not TXP.IsTXPacket(data) then
    return "非TX协议" .. nf,
      "\r\n" .. ip:hex2show() .. "\r\n" .. data:hex2show();
  end

  local data = TXP.PacketAnalyzerFix(data);
  
  local buf = txspyline:newline(data:sub(1,6));
  
  local cMainVer = buf:gb();
  local cSubVer = buf:gb();
  local wCsCmdNo = buf:gw();
  local wCsIOSeq = buf:gw();
  
  local ins = string.format("-%02X%02X-", cMainVer, cSubVer);

  local func;
  if send_or_recv then
    func = TXP.PacketSendSpy[wCsCmdNo];
  else
    func = TXP.PacketRecvSpy[wCsCmdNo];
  end

  local cmdname = TXP.PacketName[wCsCmdNo];

  if cmdname ~= nil then
    ins = ins .. cmdname;
  end
  ins = ins .. string.format("(%04X)  @ %04X", wCsCmdNo, wCsIOSeq);

  buf = txspyline:newline(data);
  local ds = "";

  if func ~= nil then
    local b, dsds = pcall(func, td, buf);
    if b then
      ds = dsds;
    else
      ds = "\r\n解析失败:" .. dsds .. "\r\n" .. data:hex2show() .. "\r\n";
    end
  end

  ds = "\r\n" .. ds .. buf.pr(buf);

  return nf .. ins,
    '\r\n' ..
    "                                                             " ..
    nf .. ip .. "\r\n" ..
    "----------------------" .. nff .. "------------------------------" ..
    ds ..
    "--------------------------------------------------------------";
end
--[=======[
    string    TXP.CreatePsMD5           ( string password )
        --指定密码字符串，返回md5

    string    TXP.CreatePsSaltMD5       ( string uin | int uin, string psmd5 )
        --指定帐号、密码md5，生成passaltmd5
]=======]
function TXP.CreatePsMD5( password )
  local password = password or "";
  return password:md5();
end

function TXP.CreatePsSaltMD5( uin, psmd5 )
  if type(uin) == "string" then
    uin = tonumber(uin);
  end
  local pssaltmd5 = txline:new();
  pssaltmd5:sa(psmd5);
  pssaltmd5:sd(0);
  pssaltmd5:sd(uin);
  return pssaltmd5.line:md5();
end

require "TXProtocol/Packet/0825";
require "TXProtocol/Packet/0836";
require "TXProtocol/Packet/0828";