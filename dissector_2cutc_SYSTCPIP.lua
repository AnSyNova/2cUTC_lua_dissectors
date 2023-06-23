--INIT
--INIT
--INIT

-- SYSTCPIP
local proto_systcpip = Proto("systcpip", "Component SYSTCPIP")

local proto_systcpip_expert = ProtoExpert.new("SYSTCPIP", "Bad result", expert.group.PROTOCOL, expert.severity.ERROR)

-- Fields that you can use in filters and coloring rules:
local systcpip_len = ProtoField.uint16("systcpip.len", "Length")
local systcpip_unknown1 = ProtoField.bytes("systcpip.unknown1", "?")
local systcpip_entid = ProtoField.uint32("systcpip.entid", "ENTID", base.HEX)
local systcpip_flag = ProtoField.string("systcpip.flag", "ENTID_FLAG")
local systcpip_option = ProtoField.string("systcpip.option", "ENTID_OPTION")
local systcpip_description = ProtoField.string("systcpip.description", "ENTID_DESCRIPTION")
local systcpip_tstp = ProtoField.uint64("systcpip.tstp", "Timestamp", base.HEX)
local systcpip_hasid = ProtoField.uint16("systcpip.hasid", "Home ASID", base.HEX)
local systcpip_pasid = ProtoField.uint16("systcpip.pasid", "Primary ASID", base.HEX)
local systcpip_sasid = ProtoField.uint16("systcpip.sasid", "Secondary ASID", base.HEX)
local systcpip_userid = ProtoField.string("systcpip.userid", "USERID")
local systcpip_ducb = ProtoField.uint32("systcpip.ducb", "DUCB", base.HEX)
local systcpip_cid   = ProtoField.uint32("systcpip.cid", "CID", base.HEX)
local systcpip_lcl_port = ProtoField.uint16("systcpip.port", "Local port")
local systcpip_rmt_ip   = ProtoField.ipv4("systcpip.rmt_ip", "Remote IP")

proto_systcpip.fields = {  
	systcpip_len,
	systcpip_unknown1, 
	systcpip_entid, 
	systcpip_flag, 
	systcpip_option, 
	systcpip_description, 
	systcpip_tstp,
	systcpip_hasid,
	systcpip_pasid,
	systcpip_sasid,
	systcpip_userid,
	systcpip_ducb,					
	systcpip_cid, 
	systcpip_lcl_port,
	systcpip_rmt_ip
}

proto_systcpip.experts = {
	proto_systcpip_expert
}

local _2cutc_extension = Field.new("2cutc.extension")

--[[
The 2cUTC extension provided for the SYSTCPIP component:

       00   01    02  03  04  05  06  07  08  09  0A    0B  0C  0D  0E  0F  ..  ..  
0000   flag blank option........................  blank description...................
]]

--DISSECTOR
--DISSECTOR
--DISSECTOR

-- SYSTCPIP
function proto_systcpip.dissector(buffer, pinfo, tree)
	length = buffer:len()
	if length == 0 then return end
	
	pinfo.cols.protocol = proto_systcpip.name

    local subtree = tree:add(proto_systcpip, buffer)

	-- get 2cUTC derived information from higher up
	local extension = _2cutc_extension().range

	local flag = extension(0, 1):string()
	local option = string.gsub(extension(2, 8):string(), "^%s*(.-)%s*$", "%1")
	local description = string.gsub(string.lower(extension(11, 32):string()), "^%s*(.-)%s*$", "%1")

	if flag == "!" then
		subtree:add_proto_expert_info(proto_systcpip_expert, "ENTID indicates error")
	end

	-- CTRACE begin length field
	local ctrace_len = buffer(0, 2):uint()
	subtree:add(systcpip_len, buffer(0, 2))

	-- dissect
	-- add to subtree here
	subtree:add(systcpip_unknown1, buffer(2, 2))
	subtree:add(systcpip_entid, buffer(4, 4))

    subtree:add(systcpip_flag, flag)
    subtree:add(systcpip_option, option)
    subtree:add(systcpip_description, description)

	local tstp_z = buffer(8, 8):uint64()
	local tstp_z_secs = ztod_2_unix(tstp_z:tonumber())/1000000
	subtree:add(systcpip_tstp, buffer(8, 8)):append_text(" (" .. format_date(tstp_z_secs) .. ")")
	
	subtree:add(systcpip_hasid, buffer(16, 2))
	subtree:add(systcpip_pasid, buffer(18, 2))
	subtree:add(systcpip_sasid, buffer(20, 2))
 	subtree:add_packet_field(systcpip_userid, buffer:range(32, 8), ENC_EBCDIC)
	subtree:add(systcpip_ducb, buffer(40, 4))
	subtree:add(systcpip_cid, buffer(52, 4))
	subtree:add(systcpip_lcl_port, buffer(48, 2))
	subtree:add(systcpip_rmt_ip, buffer(68, 4))

	-- see above, special data inserted by 2cUTC
	pinfo.cols.info:append(" " .. option .. " " .. description)
	if option == "TCP" then
		Dissector.get("systcpip_tcp"):call(buffer(2, ctrace_len - 4):tvb(), pinfo, subtree)
	end

	-- CTRACE end length field
	subtree:add(buffer(ctrace_len - 2, 2), "Length repeated: " .. buffer(ctrace_len - 2, 2):uint())
end

function ztod_2_unix(ztod)
	local offset = 9048018124800000000
    local utod = (ztod - offset) / 4096
	return utod
  end
