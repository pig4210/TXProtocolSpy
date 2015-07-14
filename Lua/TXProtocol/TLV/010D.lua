local tag = 0x010D;
local name = "TLV_SigLastLoginInfo";
local subver = 0x0001;

TXP.TLVName[tag] = name;

TXP.TLVAnalyzer[tag] = function(td, data)
end

TXP.TLVSpy[tag] = function(td, data)
  return
  data:pw("wSubVer") ..
  data:phhs("bufSigLastLoginInfo");
end