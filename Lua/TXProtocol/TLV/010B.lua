local tag = 0x010B;
local name = "TLV_QDLoginFlag";
local subver = 0x0002;

TXP.TLVName[tag] = name;

local function CreateQDFlag(s, m, tgt)
  s = s % 0x100;
  m = {m:byte(1, -1)};
  tgt = {tgt:byte(1, -1)};
  for k = 1, #tgt do
      s = s ~ tgt[k];
  end
  for k = 1, #m do
      s = s ~ m[k];
  end
  s = s % 0x100;
  return s;
end

TXP.TLVBuilder[tag] = function(td)
  local tlv = txline:new();
  local data = txline:new();
  local wSubVer = td[TXP.CreateTLVSubVerName(tag)] or subver;
  data:sw(wSubVer);
  if wSubVer == 0x0002 then
    data:sa(td.bufQQMd5);
    local ff = CreateQDFlag(1, td.bufQQMd5, td.bufTGT);
    data:sb(ff);
    data:sb(0x10);
    data:sd(0);
    data:sd(2);
    local qddata = TXP.CreateQdData(td);
    data:sha(qddata);
    data:sha("");
    data:sha("");
  else
    error(name .. "无法识别的版本号" .. wSubVer);
  end
  tlv:sw(tag);
  tlv:shl(data);
  return tlv;
end

TXP.TLVSpy[tag] = function(td, data)
  local ds = data:pw("wSubVer");
  local bufm, m = data:pkey("bufQQMd5");
  local buff, f = data:pb("QdFlag");
  ds = ds .. bufm .. buff;
  local ff = CreateQDFlag(1, m, td.SpybufTGT);
  data:inc();
  if ff == f then
    ds = ds .. data:pk() .. "chk QdFlag ok\r\n";
  else
    ds = ds .. data:pk() .. "chk QdFlag *no equ*\r\n";
  end
  data:dec();
  ds = ds ..
  data:pb("10") ..
  data:pd("00000000") ..
  data:pd("00000002");

  local bufq, QdData = data:phloh("QdData");
  QdData:inc();
  ds = ds ..
  bufq ..
      TXP.TLVSpy[0x0032](td, QdData) ..
      QdData:pr();
  ds = ds ..
  data:phhs("Unknow") ..
  data:phhs("Unknow");
  return ds;
end