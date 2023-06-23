--INIT
--INIT
--INIT

-- Top level: 2cUTC
local proto_2cutc = Proto("2cutc", "2cUTC Trace Conversion")

-- Fields that you can use in filters and coloring rules:
local _2cutc_eyecatcher = ProtoField.string("2cutc.eyecatcher", "Eyecatcher")
local _2cutc_xlen = ProtoField.uint16("2cutc.xlen", "Extension length")
local _2cutc_component = ProtoField.string("2cutc.component", "Component")
local _2cutc_extension = ProtoField.bytes("2cutc.extension", "Extension")
--[[

The following field also "exists". It is created by the respective
	postdissectors for each component, it is not defined HERE.

	Note that this field can be used just like the ones above for showing
	in columns, as a filter or for coloring rules.

local _2cutc_info = ProtoField.string("2cutc.info", "2cUTC_Info")	

]]

proto_2cutc.fields = {  
	_2cutc_eyecatcher,
	_2cutc_xlen,
	_2cutc_component,
	_2cutc_extension
}

--DISSECTOR
--DISSECTOR
--DISSECTOR

--[[

The 2cUTC CTRACE Header for Wireshark:

       00  01  02  03  04  05  06  07  08  09  0A  0B  0C  0D  0E  0F
0000   eyecatcher........  r1  xlen..  component.....................

eyecatcher = "2cUTC". component = "SYSTCPIP" (for example)

r1   = any value
xlen = length of extension in 16-byte multiples, 0 means no extension present

if r1 is 0x20 AND xlen is 0x2020, assume xlen to be 48

]]

-- Top level: 2cUTC
function proto_2cutc.dissector(buffer, pinfo, tree)
	length = buffer:len()
	if length == 0 then return end
	
	pinfo.cols.protocol = proto_2cutc.name

    local subtree = tree:add(proto_2cutc, buffer, "2cUTC Header")

    subtree:add(_2cutc_eyecatcher, buffer(0, 5), buffer(0, 5):string())

	subtree:add(buffer(5, 1), "Reserved")

	subtree:add(_2cutc_xlen, buffer(6, 2), buffer(6, 2):uint())

	-- handle legacy extensions, this code can be removed sometime soon
    local effxlen = buffer(5, 3):uint()
	if effxlen == 2105376 then
		effxlen = 48
		testlen = buffer(16, 2):uint()
		if (16 + testlen + 2) < length then
			if testlen == buffer(16 + testlen - 2, 2):uint() then
				effxlen = 0
			end
		end
	end
	if effxlen ~=  buffer(6, 2):uint() then
		subtree:add("Effective extension length: " .. effxlen)
	end

	subtree:add(_2cutc_component, buffer(8, 8),  buffer(8, 8):string())

	if effxlen > 0 then
		subtree:add(_2cutc_extension, buffer(16, effxlen),  buffer(16, effxlen):string())
		subtree:add("Extension(as string): " .. buffer(16, effxlen):string())
	end

	-- check buffer for validity
	local err_text = ""
	local ctrace_len1 = buffer(16 + effxlen, 2):uint()
	if 16 + effxlen + ctrace_len1 > length then
		err_text = "buffer too long"
	elseif 16 + effxlen + ctrace_len1 < length then
		err_text = "buffer too short"
	else
		local ctrace_len2 = buffer(16 + effxlen + ctrace_len1 - 2, 2):uint()
		if ctrace_len1 ~= ctrace_len2 then
			err_text = "ctrace lenth bytes mismatch"
		end
	end

	-- Trim trailing blanks, convert to lower case
	local diss_name = string.gsub(string.lower(buffer(8, 8):string()), "^%s*(.-)%s*$", "%1")   

	-- special case: CSQX????, last 4 chars indicate address space, reduce to "CSQX".
	if string.sub(diss_name, 1, 4) == "csqx" then
		diss_name = "csqx"
	end

	-- Get the dissector we need
	local diss = Dissector.get(diss_name)
	if not diss then
		err_text = "dissector not found"
	end
	
	-- If no errors, invoke the dissector.
	if err_text == "" then
		pinfo.cols.info = "2CUTC " .. string.upper(diss_name)
		diss:call(buffer(16 + effxlen):tvb(), pinfo, tree)
		return
	end

	pinfo.cols.info = "2CUTC " .. string.upper(diss_name) .. " " .. err_text
	subtree:add("ERROR: " .. err_text)
	subtree:add(buffer(16 + effxlen), "CTRACE Data")
end
