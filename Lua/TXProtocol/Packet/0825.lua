--[=======[
-------- -------- -------- --------
            0825 Ping包
-------- -------- -------- --------
]=======]
local cscmd = 0x0825;
TXP.PacketName[cscmd] = "Ping";
--[=======[
    string    TXP.PacketBuilder[0x0825] ( TXData td );
        --指定数据环境，生成0825 Send数据封包
]=======]
TXP.PacketBuilder[cscmd] = function(td)
  local data = txline:new();

  data:sw(cscmd);
  td.wCsIOSeq = td.wCsIOSeq + 1;
  data:sw(td.wCsIOSeq);
  data:sd(td.dwUin);

  data:sa("\x03\x00\x00");
  data:sd(td.dwClientType);
  data:sd(td.dwPubNo);
  data:sd(0);
    
  local bufCsCmdCryptKey = data:srk();

  local tlv_table =
    {
    0x0018,
    0x0008,
    0x0004,
    0x0309,
    0x0036,
    0x0114,
    };

  local tlvs = txline:new();
  for k = 1, #tlv_table do
    local func = TXP.TLVBuilder[tlv_table[k]];
    if func == nil then
      error(string.format("TLV-%04X-不存在构建函数", tlv_table[k]));
    end
    tlvs:sl( func(td) );
  end
    
  local encode = TeanEncrypt(tlvs.line, bufCsCmdCryptKey);
    
  if (encode == nil) or (#encode == 0) then
    error(string.format("Packet-%04X-加密失败", cscmd));
  end
  td.Key[TXP.CreateKeyName(cscmd, td.wCsIOSeq)] = bufCsCmdCryptKey;

  data:sa(encode);

  return TXP.PacketBuilderFix(td, data);
end

-------- -------- -------- --------
--[=======[
    TXP.PacketResultName[0x0825]        --0825封包返回结果对应说明数组
]=======]
TXP.PacketResultName[cscmd] = {};
local name = TXP.PacketResultName[cscmd];

name[0x00] = "Ping成功";
name[0xFE] = "需要重定向";
name[0xFD] = "过载保护";
name[0xF8] = "DoMain";
name[0xF9] = "要求切换TCP";
name[0xFF] = "其它错误";

-------- -------- -------- --------
--[=======[
    string    TXP.PacketAnalyzer[0x0825]( TXData td, string data | txline data );
        --指定数据环境，Recv封包，解析之
]=======]
TXP.PacketAnalyzer[cscmd] = function( td, data )
  data = TXP.PacketAnalyzerFix(data);
  if data == nil then
      return "非TX协议";
  end
  if type(data) == "string" then
    data = txline:newline(data);
  end

  local cMainVer = data:gb();
  local cSubVer = data:gb();
  local wCsCmdNo = data:gw();
  local wCsSeq = data:gw();
  local dwUin = data:gd();
  data:ga(3);

  local encode;
  local buf = data.line;
  for k, v in pairs(td.Key) do
    if k:sub(1,3) ~= "Spy" then
      encode = TeanDecrypt(buf, v);        
      if (encode ~= nil) and (#encode > 0) then
        break;
      end
    end
  end
  if (encode == nil) or (#encode <= 0) then
    return string.format("Packet-%04X-解密失败", wCsCmdNo);
  end
  --二轮解密
  local encode2;
  for k,v in pairs(td.Key) do
    if k:sub(1,3) ~= "Spy" then
      encode2 = TeanDecrypt(encode, v);
      if (encode2 ~= nil) and (#encode2 > 0) then
        buf = buf .. "   +    with " .. k;
        encode = encode2;
        break;
      end
    end
  end
    
  data.line = encode;

  td.result = data:gb();

  local rets = "";
  while #data.line > 0 do
    local tag = data:gw();
    local value = data:ghl(len);
    local func = TXP.TLVAnalyzer[tag];
    if func ~= nil then
      func(td, value);
    else
      rets = rets .. string.format("TLV %04X没有解析函数\r\n", tag);
    end
  end

  return rets;
end

-------- -------- -------- --------
--[=======[
    string    TXP.PacketSendSpy[0x0825] ( TXData td, txspyline data );
        --指定数据环境，Send封包(去头去尾，txspyline)，解析之
]=======]
TXP.PacketSendSpy[cscmd] = function(td, data)
  local cMainVer = data:gb();
  local cSubVer = data:gb();
  local wCsCmdNo = data:gw();
  local wCsSenderSeq = data:gw();

local ds = string.format("bufPacketHeader [%02X]\r\n", 0xA);
data:inc();
  ds = ds ..
    data:pk() .. string.format("cMainVer、cSubVer: %02X %02X\r\n", cMainVer, cSubVer) ..
    data:pk() .. string.format("wCsCmdNo:                                          *** %04X ***\r\n",              wCsCmdNo) ..
    data:pk() .. string.format("wCsSenderSeq:                          --- %04X ---\r\n",                          wCsSenderSeq) ..
    data:pd("dwUin");
data:dec();

ds = ds ..
data:phs("UNKNOW", 3);

ds = ds ..
data:pd("dwClientType") ..
data:pd("dwPubNo") ..
data:pd("UNKNOW");
    
  local bufCsPrefix, bufCsCmdCryptKey  =  data:pkey("bufCsPrefix");
ds = ds .. bufCsPrefix;

  td.Key[TXP.CreateSpyKeyName(wCsCmdNo, wCsSenderSeq)] = bufCsCmdCryptKey;

  local encode;
  local buf = data.line;
  for k,v in pairs(td.Key) do
    if k:sub(1,3) == "Spy" then
      encode = TeanDecrypt(buf, v);
      if (encode ~= nil) and (#encode > 0) then
        buf = "    with " .. k;
        break;
      end
    end
  end
  if (encode == nil) or (#encode <= 0) then
    return ds .. string.format("\r\nPacket-%04X-解密失败\r\n", wCsCmdNo);
  end

ds = ds ..
string.format("GeneralCodec_Request [%04X] >> [%04X]%s\r\n", #data.line, #encode, buf);

  data.line = encode;
    
  while #data.line > 0 do
    ds = ds .. data:ptlv(td);
  end

  return ds;
end

-------- -------- -------- --------
--[=======[
    string    TXP.PacketRecvSpy[0x0825] ( TXData td, txspyline data );
        --指定数据环境，Recv封包(去头去尾，txspyline)，解析之
]=======]
TXP.PacketRecvSpy[cscmd] = function(td, data)
  local cMainVer = data:gb();
  local cSubVer = data:gb();
  local wCsCmdNo = data:gw();
  local wCsSenderSeq = data:gw();

  local ds =
string.format("bufPacketHeader [%02X]\r\n", 0xA);
data:inc();
ds = ds ..
  data:pk() .. string.format("cMainVer、cSubVer: %02X %02X\r\n", cMainVer, cSubVer) ..
  data:pk() .. string.format("wCsCmdNo:                                          *** %04X ***\r\n",              wCsCmdNo) ..
  data:pk() .. string.format("wCsSenderSeq:                          --- %04X ---\r\n",                          wCsSenderSeq) ..
  data:pd("dwUin");
data:dec();

local ds = ds ..
data:phs("UNKNOW", 3);

  local encode;
  local buf = data.line;
  for k,v in pairs(td.Key) do
    if k:sub(1,3) == "Spy" then
      encode = TeanDecrypt(buf, v);
      if (encode ~= nil) and (#encode > 0) then
        buf = "    with " .. k;
        break;
      end
    end
  end
  if (encode == nil) or (#encode <= 0) then
    return ds .. string.format("Packet-%04X-解密失败\r\n", wCsCmdNo);
  end
  --二轮解密
  local encode2;
  for k,v in pairs(td.Key) do
    if k:sub(1,3) == "Spy" then
      encode2 = TeanDecrypt(encode, v);
      if (encode2 ~= nil) and (#encode2 > 0) then
        buf = buf .. "   +    with " .. k;
        encode = encode2;
        break;
      end
    end
  end

ds = ds .. data:pk() ..
string.format("GeneralCodec_Response [%04X] >> [%04X]%s\r\n", #data.line, #encode, buf);

  data.line = encode;

  local cResult = data:gb();
  local rn = TXP.PacketResultName[wCsCmdNo];
  if rn ~= nil then
    rn = rn[cResult];
  end
  rn = rn or "结果未命名";
ds = ds .. "\r\n" ..
  data:pk() .. string.format("    cResult: %02X   >>%s<<\r\n", cResult, rn);
    
  while #data.line > 0 do
    ds = ds .. data:ptlv(td);
  end

  return ds;
end