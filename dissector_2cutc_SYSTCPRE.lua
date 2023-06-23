--INIT
--INIT
--INIT

-- SYSTCPRE
local proto_systcpre = Proto("systcpre", "Component SYSTCPRE")

-- Fields that you can use in filters and coloring rules:
local systcpre_len = ProtoField.uint16("systcpre.len", "Length")
local systcpre_data = ProtoField.bytes("systcpre.data", "Data")

proto_systcpre.fields = {  
	systcpre_len,
	systcpre_data
}

--DISSECTOR
--DISSECTOR
--DISSECTOR

-- SYSTCPRE
function proto_systcpre.dissector(buffer, pinfo, tree)
	length = buffer:len()
	if length == 0 then return end
	
	pinfo.cols.protocol = proto_systcpre.name

    local subtree = tree:add(proto_systcpre, buffer, "Component SYSTCPRE")

	-- CTRACE begin length field
	local ctrace_len = buffer(0, 2):uint()
	subtree:add(systcpre_len, buffer(0, 2))

	-- dissect
	-- add to subtree here
	subtree:add(systcpre_data, buffer(2, ctrace_len - 4))

	-- CTRACE end length field
	subtree:add(buffer(ctrace_len - 2, 2), "Length repeated: " .. buffer(ctrace_len - 2, 2):uint())
end
