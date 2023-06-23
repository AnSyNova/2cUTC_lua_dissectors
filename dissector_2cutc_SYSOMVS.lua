--INIT
--INIT
--INIT

-- SYSOMVS
local proto_sysomvs = Proto("sysomvs", "Component SYSOMVS")

-- Fields that you can use in filters and coloring rules:
local sysomvs_len = ProtoField.uint16("sysomvs.len", "Length")
local sysomvs_data = ProtoField.bytes("sysomvs.data", "Data")

proto_sysomvs.fields = {  
	sysomvs_len,
	sysomvs_data
}

--DISSECTOR
--DISSECTOR
--DISSECTOR

-- SYSOMVS
function proto_sysomvs.dissector(buffer, pinfo, tree)
	length = buffer:len()
	if length == 0 then return end
	
	pinfo.cols.protocol = proto_sysomvs.name

    local subtree = tree:add(proto_sysomvs, buffer)

	-- CTRACE begin length field
	local ctrace_len = buffer(0, 2):uint()
	subtree:add(sysomvs_len, buffer(0, 2))

	-- dissect
	-- add to subtree here
	subtree:add(sysomvs_data, buffer(2, ctrace_len - 4))

	-- CTRACE end length field
	subtree:add(buffer(ctrace_len - 2, 2), "Length repeated: " .. buffer(ctrace_len - 2, 2):uint())
end
