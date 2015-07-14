require "xlua"

local filename = "tps_aly.lua";
local notes = "";
local file = io.open(filename, 'r');
local data = file:read('a');
file:close();

for note in data:gmatch("%-%-%[=======%[(.-)%]=======%]") do
  notes = notes .. "\r\n" .. note .. "\r\n";
end

local data, err = load(data);
if err then
  error(err);
  return;
end

local data = string.dump(data, true);

local file = io.open(filename:gsub(".lua", ".e.lua"), "wb");
file:write(data);
file:close();
local file = io.open(filename:gsub(".lua", ".txt"), "w");
file:write(notes);
file:close();






local filename = "analyzer.lua";
local notes = "";
local file = io.open(filename, 'r');
local data = file:read('a');
file:close();
  
for note in data:gmatch("%-%-%[=======%[(.-)%]=======%]") do
  notes = notes .. "\r\n" .. note .. "\r\n";
end

local data, err = load(data);
if err then
  error(err);
  return;
end

local data = string.dump(data, true);

local file = io.open(filename:gsub(".lua", ".e.lua"), "wb");
file:write(data);
file:close();
local file = io.open(filename:gsub(".lua", ".txt"), "w");
file:write(notes);
file:close();