
--[=======[
-------- -------- -------- --------
              TXData
-------- -------- -------- --------

    TXP.Data;                           --TXProtocol的数据环境
        --所有与配置不同的数据请在new后自行更改
]=======]
TXP.Data                    = {};
TXP.Data.__index = TXP.Data;

local td = TXP.Data;

--[=======[
    TXProtocol的数据环境有以下必要配置信息，允许预设定，但必须有值
      cMainVer                          --QQ主版本号
      cSubVer                           --QQ次版本号
      dwClientType                      --客户端类型
      dwPubNo                           --发行版本号
      wSubVer                           --子版本号
      dwSSOVersion                      --SSO版本号
      dwServiceId
      dwClientVer                       --客户端版本号
      cPingType                         --Ping类型

      QdPreFix                          --QdData前缀
      QdSufFix                          --QdData后缀
      bufQdKey                          --QdData Key
      dwQdVerion                        --这是QQProtect.exe或dll的"产品版本"
      cQdProtocolVer                    --QdData版本号
      wQdCsCmdNo                        --QdData指令号
      cQdCcSubNo                        --QdData次指令号
      cOsType                           --系统类型
      bIsWOW64                          --是否x64
      dwDrvVersionInfo                  --驱动版本信息
      bufVersion_TSSafeEdit_dat         --TSSafeEdit.dat的"文件版本"
      bufVersion_QScanEngine_dll        --QScanEngine.dll的"文件版本"
      bufQQMd5                          --QQ.exe的md5
]=======]
td.cMainVer                 = 0x36;     --0x35;
td.cSubVer                  = 0x16;     --0x3B;
td.dwClientType             = 0x00010101;
td.dwPubNo                  = 0x00006776; --0x00006717;
td.wSubVer                  = 0x0001;
td.dwSSOVersion             = 0x0000044B; --0x00000445;
td.dwServiceId              = 0x00000001;
td.dwClientVer              = 0x0000152B; --0x000014EF;
td.cPingType                = 0x04;

td.QdPreFix                 = "\x3E";
td.QdSufFix                 = "\x68";
td.bufQdKey                 = "wE7^3img#i)%h12]";
td.dwQdVerion               = 0x04000307; --0x03080202;
td.cQdProtocolVer           = 0x02;
td.wQdCsCmdNo               = 0x0004;
td.cQdCcSubNo               = 0x00;
td.cOsType                  = 0x01;                 --系统类型
td.bIsWOW64                 = 0x00;                 --是否x64
td.dwDrvVersionInfo         = 0x00000000;
td.bufVersion_TSSafeEdit_dat = str2hexs"07DE000300060001";  --"07DE000900020001";
                                                    --TSSafeEdit.dat的"文件版本"
td.bufVersion_QScanEngine_dll = str2hexs"0002000400000000";
                                                    --QScanEngine.dll的"文件版本"
td.bufQQMd5                 = str2hexs"DA864B886E555A7B4B3678B8CBB128D4";  --"0E3B8145EF65E7B3D0A9EF0A1EC5C43F";
--[=======[
    TXData    TXP.Data:new              ( string account, string password );
        --给定账号密码，新建数据环境
        --account默认0
        --password默认空串

    新的数据环境会有如下新的数据项
      dwUin                             --帐号数值
      bufPsMD5                          --密码md5
      bufPsSaltMD5                      --密码与帐号的md5
    以下配置信息需要即时计算或提取，但也允许使用固定值
      dwLocaleID                        --本地信息，中国大陆
      wTimeZoneoffsetMin                --时区差值，中国大陆
      bRememberPwdLogin                 --是否记住登陆
      bufDHPublicKey                    --本地通讯公钥
      bufDHShareKey                     --本地通讯私钥
      tlv0114subver                     --ECDH Key版本号
      dwISP
      dwIDC
    伪造计算机信息，使用账号附加数据的MD5，基于账号的固定值
      bufComputerName
      bufComputerID
      bufComputerIDEx
      bufMacGuid
      bufMachineInfoGuid
    以下信息是环境必要数据，建议不要修改
      RedirectIP                        --重定向IP组
      Key                               --加解密KEY组
      wCsIOSeq                          --通讯序号
]=======]
function TXP.Data:new(account, password)
  local data = {};
  setmetatable(data, self);
  self.__index = self;
    
  --加入帐号信息
  account = account or "0";
  if type(account) == "string" then
    data.dwUin            = tonumber(account);
  else
    data.dwUin            = account;
  end
  if (data.dwUin <= 10000) or (data.dwUin > 0xFFFFFFFF) then
    data.dwUin            = 0;
  end
    
  --计算密码MD5
  password = password or "";
  data.bufPsMD5           = TXP.CreatePsMD5(password);
  data.bufPsSaltMD5       = TXP.CreatePsSaltMD5(data.dwUin, data.bufPsMD5);
    
  --------以下配置信息需要即时计算或提取，但也允许使用固定值
  data.dwLocaleID         = 0x00000804;
  data.wTimeZoneoffsetMin = 0x01E0;
  data.bRememberPwdLogin  = 0;
  data.bufDHPublicKey     = str2hexs"025AE2EC20719448656AB942A96C558BD26E808DCD171E985A";
  data.bufDHShareKey      = str2hexs"6CE5431AF838645A665CFB68309291F3623AD05105AA0A9A";
  data.tlv0114subver      = 0x0102;       --ECDH Key版本号
  data.dwISP              = 0x00000000;
  data.dwIDC              = 0x00000000;
    
  --------伪造计算机信息，使用账号附加数据的MD5，基于账号的固定值
  data.bufComputerName    = md5(account .. "ComputerName"):hex2str();
  data.bufComputerID      = md5(account .. "ComputerID");
  data.bufComputerIDEx    = md5(account .. "ComputerIDEx");
  data.bufMacGuid         = md5(account .. "MacGuid");
  data.bufMachineInfoGuid = md5(account .. "MachineInfoGuid");
    
  --------以下信息是环境必要数据，建议不要修改
  data.RedirectIP         = {};
  data.Key                = {};
  data.wCsIOSeq           = xrand(0xFFFF) + 1;

  return data;
end
--[=======[
    TXData    TXP.Data:new_net(
        string    account,              --默认0
        string    password,             --默认空串
        string    ip,                   --连接IP地址，若为空，自行从TXP.Servers拉取一个地址
        string    port,                 --连接IP端口
        boolean   udp_or_tcp,           --指定通讯使用UDP或TCP，默认UDP
        int       timeout               --通讯超时，以ms计，默认5000ms
        );

    新的数据环境继承于TXP.Data:new
    新的数据环境有以下额外数据项
      istcp                             --是否使用TCP通讯
      link                              --通讯socket
      dwServerIP                        --通讯目标IP
      wServerPort                       --通讯目标端口
]=======]
function TXP.Data:new_net(account, password, ip, port, udp_or_tcp, timeout)
  local data = self:new(account, password);

  --默认使用udp环境
  local udp_or_tcp = udp_or_tcp or true;
  local stype = 0;
  if udp_or_tcp == false then
    stype = 1;
    data.istcp              = true;
  end

  --默认5秒超时
  local timeout = timeout or 5000;

  --如果ip为空，自行拉取一个地址
  if ip == nil then
    while true do
      local cfgip = TXP.Servers[ xrand(#TXP.Servers) + 1 ];
      if cfgip.cServerType == stype then
        ip, port = cfgip.strServerAddr, cfgip.wServerPort;
        break;
      end
    end
  end

  if type(port) == "number" then
    port = tostring(port);
  end

  --建立sock
  if stype == 0 then
      data.link             = udp_new(ip, port); 
  else
      data.link             = tcp_new(ip, port);
  end
  data.link:settimeout(timeout);
  string.format("TXProtocol连接%s:%d", ip, port):xlog();
  local sip, sport, ip, port = data.link:getpeername();
  data.dwServerIP           = ip;
  data.wServerPort          = port;

  return data;
end
--[=======[
    TXP.Servers                         --TX默认通讯IP数据库
]=======]
TXP.Servers =
{
  { ["strServerAddr"] = "sz.tencent.com", ["wServerPort"] = 8000, ["cServerType"] = 0 },
  { ["strServerAddr"] = "sz2.tencent.com", ["wServerPort"] = 8000, ["cServerType"] = 0 },
  { ["strServerAddr"] = "sz3.tencent.com", ["wServerPort"] = 8000, ["cServerType"] = 0 },
  { ["strServerAddr"] = "sz4.tencent.com", ["wServerPort"] = 8000, ["cServerType"] = 0 },
  { ["strServerAddr"] = "sz5.tencent.com", ["wServerPort"] = 8000, ["cServerType"] = 0 },
  { ["strServerAddr"] = "sz6.tencent.com", ["wServerPort"] = 8000, ["cServerType"] = 0 },
  { ["strServerAddr"] = "sz7.tencent.com", ["wServerPort"] = 8000, ["cServerType"] = 0 },
  { ["strServerAddr"] = "sz8.tencent.com", ["wServerPort"] = 8000, ["cServerType"] = 0 },
  { ["strServerAddr"] = "sz9.tencent.com", ["wServerPort"] = 8000, ["cServerType"] = 0 },

  { ["strServerAddr"] = "tcpconn.tencent.com", ["wServerPort"] = 80, ["cServerType"] = 1 },
  { ["strServerAddr"] = "tcpconn2.tencent.com", ["wServerPort"] = 80, ["cServerType"] = 1 },
  { ["strServerAddr"] = "tcpconn3.tencent.com", ["wServerPort"] = 80, ["cServerType"] = 1 },
  { ["strServerAddr"] = "tcpconn4.tencent.com", ["wServerPort"] = 80, ["cServerType"] = 1 },
  { ["strServerAddr"] = "tcpconn5.tencent.com", ["wServerPort"] = 80, ["cServerType"] = 1 },
  { ["strServerAddr"] = "tcpconn6.tencent.com", ["wServerPort"] = 80, ["cServerType"] = 1 },
    
  { ["strServerAddr"] = "112.95.240.180", ["wServerPort"] = 8000, ["cServerType"] = 0 },
  { ["strServerAddr"] = "183.60.48.174", ["wServerPort"] = 8000, ["cServerType"] = 0 },
  { ["strServerAddr"] = "119.147.45.203", ["wServerPort"] = 8000, ["cServerType"] = 0 },
  { ["strServerAddr"] = "112.90.84.10", ["wServerPort"] = 8000, ["cServerType"] = 0 },
  { ["strServerAddr"] = "125.39.205.119", ["wServerPort"] = 8000, ["cServerType"] = 0 },
    
  { ["strServerAddr"] = "112.90.84.112", ["wServerPort"] = 80, ["cServerType"] = 1 },
  { ["strServerAddr"] = "123.151.40.188", ["wServerPort"] = 80, ["cServerType"] = 1 },
  { ["strServerAddr"] = "112.95.240.48", ["wServerPort"] = 80, ["cServerType"] = 1 },
  { ["strServerAddr"] = "183.60.49.183", ["wServerPort"] = 80, ["cServerType"] = 1 },
  { ["strServerAddr"] = "119.147.45.40", ["wServerPort"] = 80, ["cServerType"] = 1 },
};