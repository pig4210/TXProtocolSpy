local tag = 0x0004;
local name = "SSO2::TLV_NonUinAccount_0x4";
local subver = 0x0000;


TXP.TLVName[tag] = name;

TXP.TLVBuilder[tag] = function(td)
  local tlv = txline:new();
  local data = txline:new();
  local wSubVer = td[TXP.CreateTLVSubVerName(tag)] or subver;
  data:sw(wSubVer);
  if wSubVer == 0x0000 then
    if td.dwUin ~= 0 then
      return tlv;
    end
    data:sw(wSubVer);
    data:sha(td.bufAccount);
  else
    error(name .. "无法识别的版本号" .. wSubVer);
  end
  tlv:sw(tag);
  tlv:shl(data);
  return tlv;
end

TXP.TLVSpy[tag] = function(td, data)
  return 
  data:pw("wSubVer") ..
  data:pha("bufAccount");
end