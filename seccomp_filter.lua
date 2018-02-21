require "libfrivpn_seccomp"

local arch = nil
local syscalls = nil
local need_arch_filter = true

local function get_arch()
	local ph = io.popen("uname -m","r")
	local arch = ph:read("*line")
	ph:close()
	return arch
end

if not syscalls then
	arch = get_arch()
	assert((arch == "x86_64") or arch:find("arm"))
	if arch == "x86_64" then
		syscalls = require "syscalls_x86_64"
	elseif arch:find("arm") then
		syscalls = require "syscalls_armel_eabi"
	end
end

SC_RET = {
	KILL = 0,
	TRAP = 0x00030000,
	ERRNO = 0x00050000,
	TRACE = 0x7ff00000,
	ALLOW = 0x7fff0000,
}

local BPF = {
	LD		= 0x00,
	LDX		= 0x01,
	ST		= 0x02,
	STX		= 0x03,
	ALU		= 0x04,
	JMP		= 0x05,
	RET		= 0x06,
	MISC    = 0x07,

	W		= 0x00,
	H		= 0x08,
	B		= 0x10,
	IMM		= 0x00,
	ABS		= 0x20,
	IND		= 0x40,
	MEM		= 0x60,
	LEN		= 0x80,
	MSH		= 0xa0,

	ADD		= 0x00,
	SUB		= 0x10,
	MUL		= 0x20,
	DIV		= 0x30,
	OR		= 0x40,
	AND		= 0x50,
	LSH		= 0x60,
	RSH		= 0x70,
	NEG		= 0x80,
	MOD		= 0x90,
	XOR		= 0xa0,

	JA		= 0x00,
	JEQ		= 0x10,
	JGT		= 0x20,
	JGE		= 0x30,
	JSET	= 0x40,
	K		= 0x00,
	X		= 0x08,
}

local function packint(val,len)
	local res = ""
	val = math.floor(val)
	if len == nil then len = 4 end
	for i=1,len do
		res = string.char(val%256) .. res
		val = math.floor(val/256)
	end
	return res
end

local function bpf_filter(code, jt, jf, k)
	return packint(code,2) .. packint(jt,1) .. packint(jf,1) .. packint(k,4)
end

local function bpf_stmt(code, k)
	return bpf_filter(code, 0, 0, k)
end

local function bpf_jump(code, k, jt, jf)
	return bpf_filter(code, jt, jf, k)
end

local function install_filter(t)
	if need_arch_filter then
		local my_arch = seccomp_arch()
		local t = {}
		-- load arch
		table.insert(t,bpf_stmt(BPF.LD+BPF.W+BPF.ABS, 4))
		-- compare to arch, skip if equal
		table.insert(t,bpf_jump(BPF.JMP+BPF.JEQ+BPF.K, my_arch, 1, 0))
		-- return kill if arch not equal
		table.insert(t,bpf_stmt(BPF.RET+BPF.K, SC_RET.KILL))
		-- return allow otherwise
		table.insert(t,bpf_stmt(BPF.RET+BPF.K, SC_RET.ALLOW))
		seccomp_filter(t)
		need_arch_filter = false
	end
	if t and #t >= 1 then
		return seccomp_filter(t)
	end
end

function seccomp_filter_syscalls(sc,rc,policy)
	assert((rc == SC_RET.KILL) or (rc == SC_RET.TRAP) or (rc == SC_RET.ALLOW)
		or (rc == SC_RET.ERRNO) or (rc == SC_RET.TRACE))
	assert((policy == SC_RET.KILL) or (policy == SC_RET.TRAP) or 
		(policy == SC_RET.ALLOW) or (policy == SC_RET.ERRNO) or (policy == SC_RET.TRACE))
	
	local t = {}
	
	-- load syscall number
	table.insert(t,bpf_stmt(BPF.LD+BPF.W+BPF.ABS, 0))
	
	for k,v in ipairs(sc) do
		local scn = syscalls[v]
		if type(v) == "number" then scn = v end
		if scn then
			--assert(scn,"unknown syscall: "..v)
			--print(scn)
			table.insert(t,bpf_jump(BPF.JMP+BPF.JEQ+BPF.K, scn, 0, 1))
			table.insert(t,bpf_stmt(BPF.RET+BPF.K, rc))
		end
	end
	
	-- default policy
	table.insert(t, bpf_stmt(BPF.RET+BPF.K, policy))
	install_filter(t)
end

-- example:
--[[
local good_syscalls = {
	"write",
	"rt_sigaction",
	"munmap",
	"exit_group",
	"prctl",
	"brk"
}

print("installing seccomp filters")
print("next line should be readable")
seccomp_filter_syscalls(good_syscalls,SC_RET.ALLOW,SC_RET.TRAP)
print("OHAI!")
print("now you should see the test being terminated")
seccomp_filter_syscalls({"write"},SC_RET.TRAP,SC_RET.ALLOW) -- blacklist write
print("this should NOT be readable!")
]]--
--[[ TODO:
add subtables for alternative syscalls like mmap/mmap2
good_syscalls = {
	{"mmap", "mmap2"},
	...
}
]]--
