local tag = 0x0112;
local name = "SSO2::TLV_SigIP2_0x112";


TXP.TLVName[tag] = name;

TXP.TLVBuilder[tag] = function(td)
  local tlv = txline:new();
  local data = txline:new();
  data:sa(td.bufSigClientAddr);
  tlv:sw(tag);
  tlv:shl(data);
  return tlv;
end

TXP.TLVAnalyzer[tag] = function(td, data)
  td.bufSigClientAddr = data.line;
end

TXP.TLVSpy[tag] = function(td, data)
  return 
  data:phs("bufSigClientAddr?", #data.line);
end