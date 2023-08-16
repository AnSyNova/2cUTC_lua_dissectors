--[[
	2cUTC GSKSRVR dissector
    Copyright (C) 2023  Michael Stiemke

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License along
    with this program; if not, write to the Free Software Foundation, Inc.,
    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
]]

--INIT
--INIT
--INIT

-- GSKSRVR
local proto_gsksrvr = Proto("gsksrvr", "Component GSKSRVR")

local proto_gsksrvr_expert = ProtoExpert.new("GSKSRVR", "SSL ERROR", expert.group.PROTOCOL, expert.severity.ERROR)

-- Fields that you can use in filters and coloring rules:
local gsksrvr_len = ProtoField.uint16("gsksrvr.len", "Length")
local gsksrvr_rsv1 = ProtoField.bytes("gsksrvr.rsv1", "?")
local gsksrvr_entry_id = ProtoField.uint32("gsksrvr.entry_id", "Entry ID", base.HEX)
local gsksrvr_tstp = ProtoField.uint64("gsksrvr.TSTP", "Timestamp", base.HEX)
local gsksrvr_job = ProtoField.string("gsksrvr.stack", "Job")
local gsksrvr_process = ProtoField.uint32("gsksrvr.process", "Process", base.HEX)
local gsksrvr_rsv4 = ProtoField.bytes("gsksrvr.rsv4", "?")
local gsksrvr_thread = ProtoField.uint32("gsksrvr.thread", "Thread")
local gsksrvr_desc = ProtoField.uint32("gsksrvr.desc", "Description", base.HEX)
local gsksrvr_rsv6 = ProtoField.bytes("gsksrvr.rsv6", "?")
local gsksrvr_text = ProtoField.string("gsksrvr.text", "Text")

proto_gsksrvr.fields = {  
	gsksrvr_len,
	gsksrvr_rsv1,
	gsksrvr_entry_id,
	gsksrvr_tstp,
	gsksrvr_job,
	gsksrvr_process,
	gsksrvr_rsv4,
	gsksrvr_thread,
	gsksrvr_desc,
	gsksrvr_rsv6,
	gsksrvr_text
}

proto_gsksrvr.experts = {
	proto_gsksrvr_expert
}

local _2cutc_extension = Field.new("2cutc.extension")

--[[
The 2cUTC extension provided for the GSKSRVR component:

       00   01    02  03  04  05  06  07  08  09  0A    0B  0C  0D  0E  0F  ..  ..  
0000   command padded by blanks...................
]]

--DISSECTOR
--DISSECTOR
--DISSECTOR

-- GSKSRVR
function proto_gsksrvr.dissector(buffer, pinfo, tree)
	length = buffer:len()
	if length == 0 then return end
	
	pinfo.cols.protocol = proto_gsksrvr.name

    local subtree = tree:add(proto_gsksrvr, buffer())

	-- get 2cUTC derived information from higher up
	local extension = _2cutc_extension().range

	local command = string.gsub(extension:string(), "^%s*(.-)%s*$", "%1")
	pinfo.cols.info:append(" " .. command)

	-- CTRACE begin length field
	local ctrace_len = buffer(0, 2):uint()
	subtree:add(gsksrvr_len, buffer(0, 2))

	-- dissect
	-- add to subtree here
	subtree:add(gsksrvr_rsv1, buffer(2, 2))

	--subtree:add(gsksrvr_entry_id, buf(4, 4))
	local entry_id_number = buffer(4 ,4):uint()
	local entry_id_mnem = get_entry_id_mnem(entry_id_number)
	subtree:add(gsksrvr_entry_id, buffer(4, 4)):append_text(" (" .. entry_id_mnem .. ")")

	--subtree:add(gsksrvr_tstp, buf(8, 8))
	local tstp_z = buffer(8, 8):uint64()
	local tstp_z_secs = ztod_2_unix(tstp_z:tonumber())/1000000
	subtree:add(gsksrvr_tstp, buffer(8, 8)):append_text(" (" .. format_date(tstp_z_secs) .. ")")

	subtree:add_packet_field(gsksrvr_job, buffer:range(16, 8), ENC_EBCDIC)

	subtree:add(gsksrvr_process, buffer(24, 4))

	subtree:add(gsksrvr_rsv4, buffer(28, 4))

	subtree:add(gsksrvr_thread, buffer(32, 4))

	--subtree:add(gsksrvr_desc, buffer(36, 4))
	local entry_id_descn = buffer(36 ,4):uint()
	local entry_id_descr = get_entry_id_desc(entry_id_descn)
	subtree:add(gsksrvr_desc, buffer(36, 4)):append_text(" (" .. entry_id_descr .. ")")

	if entry_id_descr == "SSL_ERROR" then
		subtree:add_proto_expert_info(proto_gsksrvr_expert, "SSL Error")
	end

	subtree:add(gsksrvr_rsv6, buffer(40, 4))

	local buftemp = buffer:range(44, ctrace_len - 44 - 2)

	-- this string will sadly terminate on the first occurrence of 0x00
	subtree:add_packet_field(gsksrvr_text, buftemp, ENC_EBCDIC)

	-- translate all 0x00 values to EBCDIC blank 0x40
	local bufbytes = buftemp:bytes()
	for i = 0, bufbytes:len() - 1 do
		if bufbytes:get_index(i) == 0 then
			bufbytes:set_index(i, 64)
		end
	end

	local bufnew = ByteArray.tvb(bufbytes)
	subtree:add(bufnew(0), "Complete text field: " .. bufnew(0):string(ENC_EBCDIC))

	-- CTRACE end length field
	subtree:add(buffer(ctrace_len - 2, 2), "Length repeated: " .. buffer(ctrace_len - 2, 2):uint())
end

function get_entry_id_mnem(entid)
	local mnem = "Unknown"
  
		if entid ==   1 then mnem = "MESSAGE"
	elseif entid ==   2 then mnem = "MESSAGE"
	elseif entid ==   4 then mnem = "MESSAGE"
	elseif entid ==   8 then mnem = "MESSAGE"
	elseif entid ==  16 then mnem = "DUMP"
	elseif entid ==  32 then mnem = "DUMP" end
  
	return mnem
  end

  function get_entry_id_desc(entid)
	local desc = "Unknown"
  
		if entid ==   1 then desc = "SSL_ENTRY"
	elseif entid ==   2 then desc = "SSL_EXIT"
	elseif entid ==   4 then desc = "SSL_ERROR"
	elseif entid ==   8 then desc = "SSL_INFO"
	elseif entid ==  16 then desc = "SSL_EBCDIC_DUMP" 
    elseif entid ==  32 then desc = "SSL_ASCII_DUMP" end
  
	return desc
  end

  function ztod_2_unix(ztod)
	local offset = 9048018124800000000
    local utod = (ztod - offset) / 4096
	return utod
  end