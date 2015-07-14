local tag = 0x0100;
local name = "SSO2::TLV_ErrorCode_0x100";


TXP.TLVName[tag] = name;

TXP.TLVAnalyzer[tag] = function(td, data)
    --不处理，故意做空
end

TXP.TLVSpy[tag] = function(td, data)
  local ds = 
  data:pw("wSubVer") .. 
  data:pw("wCsCmd") ..
  data:pd("ErrorCode") ..
  data:ph8("ErrorMsg")
  return ds;
end