require "xlua";

require "TXProtocol/TXProtocol";

local td = TXP.Data:new();

local function pick_data( data )
  if data:find("bufPwd%s*=") then
    td.bufPsMD5 = data:match("\"(%x+)\""):str2hexs();

  elseif data:find("bufDHPublicKey%s*=") then
    td.bufDHPublicKey = data:match("\"(%x+)\""):str2hexs();

  elseif data:find("bufDHShareKey%s*=") then
    td.bufDHShareKey = data:match("\"(%x+)\""):str2hexs();

  elseif data:find("strAccount%s*=") then
    td.dwUin = tonumber(data:match("\"(%x+)\""));

  end
end

function analyzer( data )
  local ins = "";
  local ds = "";

  local flag = data:sub(1,2);
  ins, ds = data:match("([^=]+)=(.*)");

  if flag == "¡ý" then
  elseif flag == "¡ø" then
      pick_data( ds );
  elseif flag == "¡ñ" then
      return TXP.PacketSpy(td, ins:sub(3), ds, true);
  elseif flag == "¡ð" then
      return TXP.PacketSpy(td, ins:sub(3), ds, false);
  else
      return "¡ìÎ´ÖªÐ­Òé", data:hex2show();
  end
  return ins, ds;
end