local tag = 0x001E;
local name = "SSO2::TLV_GTKey_TGTGT_0x1e";


TXP.TLVName[tag] = name;


TXP.TLVAnalyzer[tag] = function(td, data)
  td.Key["bufTGTGTKey"] = data:gk();
end

TXP.TLVSpy[tag] = function(td, data)
  local ds ,bufTGTGTKey = data:pkey("bufTGTGTKey");
  td.Key["SpybufTGTGTKey"] = bufTGTGTKey;
  return ds;
end