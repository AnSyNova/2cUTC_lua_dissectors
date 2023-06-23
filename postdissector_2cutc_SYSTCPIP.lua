--INIT
--INIT
--INIT

local proto_systcpip_post = Proto("systcpip_post","2cUTC info field from SYSTCPIP")

-- we define a "2cutc.info" field

local info_field = ProtoField.string("2cutc.info", "2cUTC_Info")
proto_systcpip_post.fields = { info_field }

-- any fields from 2cUTC itself?
local _2cutc_eyecatcher = Field.new("2cutc.eyecatcher")
local _2cutc_xlen = Field.new("2cutc.xlen")
local _2cutc_component = Field.new("2cutc.component")
local _2cutc_extension = Field.new("2cutc.extension")

-- any fields from SYSTCPIP?
local systcpip_flag = Field.new("systcpip.flag")
local systcpip_option = Field.new("systcpip.option")
local systcpip_description = Field.new("systcpip.description")

register_postdissector(proto_systcpip_post)

--POSTDISSECTOR
--POSTDISSECTOR
--POSTDISSECTOR

function proto_systcpip_post.dissector(tvb, pinfo, tree)

    -- only handle packets that have gone through the 2cUTC dissector
    if _2cutc_eyecatcher() == nil then return end

    local component = _2cutc_component().value

    if component ~= "SYSTCPIP" then return end

    if systcpip_flag() == nil then return end

    local info = nil -- initially empty, to be filled below in some cases

    -- fill info here
    --[[ 
        This component indicates errors when the systcpip.flag field is "!"
        and sets the error text in the systcpip.description field. 
    ]]
    local flag = systcpip_flag().value
    if flag == "!" then
        info = systcpip_description().value
    end

    -- if info has been filled by any of the above, move it into the info_field
    if info ~= nil then
         tree:add(info_field, info)
    end

end
