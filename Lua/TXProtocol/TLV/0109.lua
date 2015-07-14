local tag = 0x0109;
local name = "SSO2::TLV_0xddReply_0x109";


TXP.TLVName[tag] = name;

TXP.TLVAnalyzer[tag] = function(td, data)
  local wSubVer = data:gw();
  if wSubVer == 0x0001 then
    td.Key.bufSessionKey = data:gk();
    td.bufSigSession = data:gha();
    td.bufPwdForConn = data:gha();
    data:gha();
  else
    error(name .. "无法识别的版本号" .. wSubVer);
  end
end

TXP.TLVSpy[tag] = function(td, data)
  local ds = data:pw("wSubVer");
  local bufk, bufSessionKey  =  data:pkey("bufSessionKey");
  td.Key["SpybufSessionKey"] = bufSessionKey;
ds = ds ..
  bufk ..
  data:phhs("bufSigSession") ..
  data:phhs("bufPwdForConn") ..
  data:phhs("bufBill");
  return ds;
end