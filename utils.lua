
if socket == nil then socket = require("socket") end

function sleep(n)
	-- keep the LUA interpreter responsive in case ctrl+c is pressed
	while n >= 1 do
		socket.select(nil, nil, 1)
		n = n - 1
	end
	if n>0 then
		socket.select(nil, nil, n)
	end
end

function gettime()
	return socket.gettime()
end

eta = {}

function eta:new()
	local res = {}
	setmetatable(res, self)
	self.__index = self
	res.working = false
	res.timecnt = 0
	res.start_time = 0
	return res
end

function eta:start_work()
	if self.working then return end
	self.start_time = gettime()
	self.working = true
end

function eta:stop_work()
	if self.working ~= true then return end
	self.timecnt = self.timecnt + (gettime() - self.start_time)
	self.start_time = 0
	self.working = false
end

function eta:clear_estimate()
	self:stop_work()
	self.timecnt = 0
end

function eta:remaining_seconds(jobs_done, jobs_remaining)
	-- update timecnt if currently working
	if self.working == true then
		self:stop_work()
		self:start_work()
	end
	if not (self.timecnt > 0) then return end
	if jobs_done <= 0 then return end
	local time_per_job = self.timecnt / jobs_done
	local remaining_time = jobs_remaining * time_per_job
	return math.floor(remaining_time)
end

function eta:remaining_time(jobs_done, jobs_remaining)
	local remaining = self:remaining_seconds(jobs_done, jobs_remaining)
	if remaining == nil then return end
	local secs = remaining%60
	remaining = math.floor(remaining/60)
	local mins = remaining%60
	remaining = math.floor(remaining/60)
	local hours = remaining%24
	local days = math.floor(remaining/24)
	local res = ""
	local function plural(str,val)
		if val ~= 1 then return str.."s" else return str end
	end
	if days > 0 then 
		res = days .. " "..plural("day",days)..", " 
	end
	if hours > 0 or #res>0 then 
		res = res .. hours .. " "..plural("hour",hours)..", " 
	end
	if mins > 0 or #res>0 then 
		res = res .. mins .. " "..plural("minute",mins)..", "
	end
	if secs > 0 or #res>0 then 
		res = res .. secs .. " "..plural("second",secs)..", " 
	end
	if #res < 1 then 
		res = "0 seconds, " 
	end
	return res:sub(1, -3)
end

function eta:finish_date(jobs_done, jobs_remaining)
	local remaining = self:remaining_seconds(jobs_done, jobs_remaining)
	if remaining == nil then return end
	local now = gettime()
	local finish = now + remaining
	return os.date("%c", finish)
end

throttle = {}

function throttle:delay(args)
	local now = gettime()
	-- first call, no delay needed
	if self.last_time == nil then
		self.last_time = now
		return 0
	end
	local delay = (self.last_time + self.delayval) - now
	delay = math.max(delay, 0) -- handle negative delays
	if delay > 0 then
		if args ~= nil and args.wait == false then return delay end
		sleep(delay)
		delay = 0
	end
	-- reset timer unless prevented by user
	if args == nil or args.reset ~= false then
		self.last_time = gettime()
	end
	return delay
end

function throttle:new(rate)
	local res = {}
	setmetatable(res, self)
	self.__index = self
	res.delayval = 1/rate
	return res
end

fakesock = {}

function fakesock:setfd(fd)
	self.fd=fd
end

function fakesock:getfd(fd)
	return self.fd
end

function fakesock:new(fd)
	local res = {}
	setmetatable(res, self)
	self.__index = self
	res.fd = fd
	return res
end

databuf = {}

function databuf:get(bytes)
	return self.data:sub(1,bytes)
end

function databuf:consume(bytes)
	local len = bytes or #self.data
	local res = self.data:sub(1,len)
	self.data = self.data:sub(1+len)
	return res
end

function databuf:new(data)
	local res = {}
	setmetatable(res, self)
	self.__index = self
	res.data = data
	return res
end

function tohex(buf,space)
	local md = space or 1
	if type(buf) == "number" then
		return string.format('%02x', buf)
	end
	local str = ""
	if buf == nil then return "<nil>" end
	for i=1,#buf do
		str = str .. string.format('%02x', buf:byte(i))
		if i % md == 0 then str = str .. " " end
	end
	if #str > 1 then
		--str = str:sub(1, -2)
	end
	return str
end

function fromhex(s)
	if (s == nil) or (s == "<nil>") then return nil end
	local res = string.gsub(s, "%s*(%x%x)%s*", 
			function (h)
				return string.char(tonumber(h, 16))
			end)
	return res
end

function packint(val,len)
	local res = ""
	val = math.floor(val)
	if len == nil then len = 4 end
	for i=1,len do
		res = string.char(val%256) .. res
		val = math.floor(val/256)
	end
	return res
end

function unpackint(str)
	local res = 0
	for i = 1, #str do
		res = res + string.byte(str, i) * 256^(#str-i)
	end
	return res
end

function dump_table(t,prefix)
	local k,v
	if prefix == nil then prefix = " " end
	for k,v in pairs(t) do 
		if type(v) == "table" then dump_table(v," "..prefix..k..".")
		else print(prefix..tostring(k).."=",v) end
	end
end

function list_funcs(p1,p2)
	local tbl = _G
	local str
	if type(p1) == "table" then 
		tbl = p1
	elseif type(p1) == "string" then
		str = p1
	end
	if type(p2) == "string" then
		str = p2
	end
	for k,v in pairs(tbl) do
		if type(v) == "function" and 
			(str == nil or string.find(k,str) ~= nil) then
			print(k)
		end
	end
end

function file_exists(name)
	local f=io.open(name,"r")
	if f ~= nil then 
		io.close(f)
		return true 
	else 
		return false
	end
end

function readfile(file)
    local f = io.open(file, "r")
    local content = f:read("*all")
    f:close()
    return content
end

function prettynum(num,suffix)
	local units = {"", "k", "M", "G", "T"}
	local idx = 1
	local precision = 0
	while num >= 1000 do
		num = num / 1000
		idx = idx + 1
		precision = 2
	end
	local sfx = suffix or ""
	if precision == 2 then
		return string.format("%-4.2f %1s%s",num,units[idx],sfx)
	else
		return string.format("%4d %1s%s",num,units[idx],sfx)
	end
end

function printable(str)
	return str:gsub("[^%g ]","")
end
