--INIT
--INIT
--INIT

-- CSQX
local proto_csqx = Proto("csqx", "Component CSQX")

-- Fields that you can use in filters and coloring rules:
local csqx_len = ProtoField.uint16("csqx.len", "Length")
local csqx_data = ProtoField.bytes("csqx.data", "Data")

proto_csqx.fields = {  
	csqx_len,
	csqx_data
}

--DISSECTOR
--DISSECTOR
--DISSECTOR

-- CSQX
function proto_csqx.dissector(buffer, pinfo, tree)
	length = buffer:len()
	if length == 0 then return end
	
	pinfo.cols.protocol = proto_csqx.name

    local subtree = tree:add(proto_csqx, buffer)

	-- CTRACE begin length field
	local ctrace_len = buffer(0, 2):uint()
	subtree:add(csqx_len, buffer(0, 2))

	-- dissect
	-- add to subtree here
	subtree:add(csqx_data, buffer(2, ctrace_len - 4))

	-- CTRACE end length field
	subtree:add(buffer(ctrace_len - 2, 2), "Length repeated: " .. buffer(ctrace_len - 2, 2):uint())
end
