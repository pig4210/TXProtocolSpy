local tag = 0x0007;
local name = "TLV_TGT";
local subver = 0x0001;


TXP.TLVName[tag] = name;

TXP.TLVBuilder[tag] = function(td)
  local tlv = txline:new();
  local data = txline:new();
  data:sa(td.bufTGT);
  tlv:sw(tag);
  tlv:shl(data);
  return tlv;
end

TXP.TLVSpy[tag] = function(td, data)
  td.SpybufTGT = data.line;
  return data:phs("bufTGT", #data.line);
end