local tag = 0x0114;
local name = "SSO2::TLV_DHParams_0x114";
local subver = 0x0102;


TXP.TLVName[tag] = name;

TXP.TLVBuilder[tag] = function(td)
  local data = txline:new();
  local tlv = txline:new();
  local wSubVer = td[TXP.CreateTLVSubVerName(tag)] or subver;
  data:sw(wSubVer);
  if wSubVer == 0x0102 then
    data:sha(td.bufDHPublicKey);
  else
    error(name .. "无法识别的版本号" .. wSubVer);
  end
  tlv:sw(tag);
  tlv:shl(data);
  return tlv;
end

TXP.TLVSpy[tag] = function(td, data)
  return 
  data:pw("wDHVer") ..
  data:phhs("bufDHPublicKey");
end