local tag = 0x030F;
local name = "SSO2::TLV_ComputerName_0x30f";

TXP.TLVName[tag] = name;

TXP.TLVBuilder[tag] = function(td)
  local data = txline:new();
  local tlv = txline:new();
  data:sha(td.bufComputerName);
  tlv:sw(tag);
  tlv:shl(data);
  return tlv;
end

TXP.TLVSpy[tag] = function(td, data)
  return 
  data:pha("ComputerName");
end