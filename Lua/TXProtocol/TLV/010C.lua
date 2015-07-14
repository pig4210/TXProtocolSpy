local tag = 0x010C;
local name = "TLV_010C";
local subver = 0x0001;

TXP.TLVName[tag] = name;

TXP.TLVAnalyzer[tag] = function(td, data)
  local wSubVer = data:gw();
  if wSubVer == 0x0001 then
    td.Key.buf16byteSessionKey = data:gk();
  else
    error(name .. "无法识别的版本号" .. wSubVer);
  end
end


TXP.TLVSpy[tag] = function(td, data)
xlog(data.line:hex2show());
  local ds = data:pw("wSubVer");
  local bufk, sk = data:pkey("buf16byteSessionKey");
  td.Key.Spybuf16byteSessionKey = sk;
  ds = ds .. bufk ..
  data:pd("dwUin") ..
  data:pip("dwClientIP") ..
  data:pw("wClientPort") ..
  data:ptm("dwServerTime") ..
  data:pd("UNKNOW") ..
  data:pb("cPassSeqID") ..
  data:pip("dwConnIP") ..
  data:pip("dwReLoginConnIP") ..
  data:pd("dwReLoginCtrlFlag") ..
  data:phhs("bufComputerIDSig");
  local head_size = data.head_size;
  data.head_size = 1;
  ds = ds .. data:phhs("UNKNOW");
  data.head_size = head_size;
  local bufi, ip = data:phloh("UNKNOW");
  ip:inc();
  ds = ds .. bufi ..
      ip:pb("UNKNOW") ..
      ip:pip("dwConnIP");
  return ds;
end