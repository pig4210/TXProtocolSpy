local tag = 0x0312;
local name = "SSO2::TLV_Misc_Flag_0x312";

TXP.TLVName[tag] = name;

TXP.TLVBuilder[tag] = function(td)
  local tlv = txline:new();
  local data = txline:new();
  data:sb(1);
  data:sd(0);
  tlv:sw(tag);
  tlv:shl(data);
  return tlv;
end

TXP.TLVSpy[tag] = function(td, data)
  return  
  data:pb("01") ..
  data:pd("00000000");
end