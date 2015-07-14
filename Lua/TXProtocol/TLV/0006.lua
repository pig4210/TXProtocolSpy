local tag = 0x0006;
local name = "SSO2::TLV_TGTGT_0x6";
local subver = 0x0002;


TXP.TLVName[tag] = name;

TXP.TLVBuilder[tag] = function(td)
  local tlv = txline:new();
  local data = txline:new();
  local wSubVer = td[TXP.CreateTLVSubVerName(tag)] or subver;
  if wSubVer == 0x0002 then
    if td.bufTGTGT ~= nil then        
      tlv:sw(tag);
      tlv:sha(td.bufTGTGT);
      return tlv;
    end
    data:sd(xrand(0xFFFFFFFF) + 1);
    data:sw(wSubVer);
    data:sd(td.dwUin);
    data:sd(td.dwSSOVersion);
    data:sd(td.dwServiceId);
    data:sd(td.dwClientVer);
    data:sw(0);
    data:sb(td.bRememberPwdLogin);
    data:sa(td.bufPsMD5);
    data:sd(td.dwServerTime);
    data:sa(string.rep('\x00', 0xD));
    data:sd(td.dwClientWanIP);
    data:sd(td.dwISP);
    data:sd(td.dwIDC);
    data:sha(td.bufComputerIDEx);

    local bufTGTGTKey = td.Key["bufTGTGTKey"];
    if bufTGTGTKey == nil then
      bufTGTGTKey = data:srk();
    else
      data:sa(bufTGTGTKey); 
    end

    --print(hex2show(data.line));
    local encode = TeanEncrypt(data.line, td.bufPsSaltMD5);
    
    if (encode == nil) or (#encode == 0) then
      error(name .. "加密失败");
    end
    data.line = encode;

    td.Key["PsMD5"] = td.bufPSMD5;
    td.Key["PsSaltMD5"] = td.bufPSSALTMD5;
    td.Key["bufTGTGTKey"] = bufTGTGTKey;
    td.bufTGTGT = encode;
    --print("tgtgt:" .. hex2str(td.bufTGTGT) .. "\r\n");
  else
    error("TLV TGTGT无法识别的版本号");
  end
  tlv:sw(tag);
  tlv:shl(data);
  return tlv;
end

TXP.TLVAnalyzer[tag] = function(td, data)
  td.bufTGTGT = data.line;
end

TXP.TLVSpy[tag] = function(td, data)
  local ds = "";
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
    ds = ds .. name .. " 解密失败\r\n";
    return ds;
  end
  td.SpybufTGTGT = data.line;
ds = ds .. data:pk() ..
  string.format("tgtgt [%04X] >> [%04X]%s\r\n", #data.line, #encode, buf);
  data.line = encode;
  data:inc();
ds = ds ..
    data:pd("dwRand") ..
    data:pw("wSubVer") ..
    data:pd("dwUin") ..
    data:pd("dwSSOVersion") ..
    data:pd("dwServiceId") ..
    data:pd("dwClientVer") ..
    data:pw("UNKNOW") ..
    data:pb("bRememberPwdLogin") ..
    data:pkey("bufPsMD5") ..
    data:ptm("dwServerTime") ..
    data:phs("bufFixNull", 0xD) ..
    data:pip("dwClientWanIP") ..
    data:pd("dwISP") ..
    data:pd("dwIDC") ..
    data:phhs("bufComputerIDEx");
  local bufkey, bufTGTGTKey = data:pkey("bufTGTGTKey");
  td.Key["SpybufTGTGTKey"] = bufTGTGTKey;
  data:dec();
ds = ds .. bufkey;
  return ds; 
end