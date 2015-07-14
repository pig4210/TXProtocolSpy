local tag = 0x0103;
local name = "SSO2::TLV_SID_0x103";
local subver = 0x0001;


TXP.TLVName[tag] = name;

TXP.TLVBuilder[tag] = function(td)
  local tlv = txline:new();
  local data = txline:new();
  local wSubVer = td[TXP.CreateTLVSubVerName(tag)] or subver;
  data:sw(wSubVer);
  if wSubVer == 0x0001 then
    if td.bufSID == nil then
      return tlv;
    end
    data:sha(td.bufSID);
  else
    error(name .. "无法识别的版本号" .. wSubVer);
  end
  return tlv;
end

TXP.TLVAnalyzer[tag] = function(td, data)
  local wSubVer = data:gw();
  if wSubVer == 0x0001 then
     td.bufSID = data:gha();
  else
     error(name .. "无法识别的版本号" .. wSubVer);
  end
end

TXP.TLVSpy[tag] = function(td, data)
  return
  data:pw("wSubVer") ..
  data:phhs("bufSID");
end