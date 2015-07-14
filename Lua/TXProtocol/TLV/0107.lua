local tag = 0x0107;
local name = "SSO2::TLV_TicketInfo_0x107";
local subver = 0x0001;


TXP.TLVName[tag] = name;

TXP.TLVAnalyzer[tag] = function(td, data)
  local wSubVer = data:gw();
  if wSubVer == 0x0001 then
    local bufTickStatus = data:ghl();
        td.dwTGTServiceID = bufTickStatus:gd();
        td.dwTGTPriority = bufTickStatus:gd();
        td.dwTGTRefreshInterval = bufTickStatus:gd();
        td.dwTGTValidInterval = bufTickStatus:gd();
        td.dwTGTTryInterval = bufTickStatus:gd();
        td.wTGTTryCount = bufTickStatus:gw();
    td.Key["bufTGT_GTKey"] = data:gk();
    td.bufTGT = data:gha();
    td.Key["buf16bytesGTKey_ST"] = data:gk();
    td.bufServiceTicket = data:gha();
    local bufSTHttp = data:ghl();
        td.bAllowPtlogin = bufSTHttp:gb();
        td.Key["buf16bytesGTKey_STHttp"] = bufSTHttp:gk();
        td.bufServiceTicketHttp = bufSTHttp:gha();
    td.Key["bufGTKey_TGTPwd"] = data:gk();
  else
    error(name .. "无法识别的版本号" .. wSubVer);
  end
end

TXP.TLVSpy[tag] = function(td, data)
  local ds = data:pw("wSubVer");
  local bufTickStatus = data:ghl();
  bufTickStatus:inc();
ds = ds ..
    data:pn("bufTickStatus") .. string.format("(%04X)\r\n", #bufTickStatus.line) ..
        bufTickStatus:pd("dwTGTServiceID") ..
        bufTickStatus:pd("dwTGTPriority") ..
        bufTickStatus:pd("dwTGTRefreshInterval") ..
        bufTickStatus:pd("dwTGTValidInterval") ..
        bufTickStatus:pd("dwTGTTryInterval") ..
        bufTickStatus:pw("wTGTTryCount") ..
        bufTickStatus:pr();
  local bufk, key = data:pkey("bufTGT_GTKey");
  td.Key["SpybufTGT_GTKey"] = key;
ds = ds ..
    bufk ..
    data:phhs("bufTGT");
  bufk, key = data:pkey("buf16bytesGTKey_ST");
  td.Key["Spybuf16bytesGTKey_ST"] = key;
ds = ds ..
    bufk ..
    data:phhs("bufServiceTicket");
    
  local buft, bufSTHttp = data:phloh("bufSTHttp");
  bufSTHttp:inc();
ds = ds .. buft ..
        bufSTHttp:pb("bAllowPtlogin");
  bufk, key = bufSTHttp:pkey("buf16bytesGTKey_STHttp");
  td.Key["Spybuf16bytesGTKey_STHttp"] = key;
ds = ds ..
        bufk ..
        bufSTHttp:phhs("bufServiceTicketHttp") ..
        bufSTHttp:pr();
        
  local bufk, key = data:pkey("bufGTKey_TGTPwd");
  td.Key["SpybufGTKey_TGTPwd"] = key;
ds = ds ..
    bufk;
  return ds;
end
