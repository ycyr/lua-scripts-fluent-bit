function a10_filter(tag, ts, record)
    local msg = record["message"]
    

    if msg and string.match(msg, "^A10.*") then
        -- Pattern "A10" found in message, drop the record
        return -1, 0, 0
    else
        -- Pattern "A10" not found, keep the record
	return 0, 0, 0
    end
end


function is_cp1252_or_iso8859_1(str)
    local i, len = 1, #str
    while i <= len do
        local c = str:byte(i)
        if c >= 0x00 and c <= 0x7F then
            -- Single byte (ASCII) character, common in UTF-8, CP1252, and ISO-8859-1
            i = i + 1
        elseif (c >= 0xC2 and c <= 0xDF) and (i + 1 <= len) and
               (str:byte(i + 1) >= 0x80 and str:byte(i + 1) <= 0xBF) then
            -- Start of a 2-byte UTF-8 character
            return false
        elseif (c >= 0xE0 and c <= 0xEF) and (i + 2 <= len) and
               (str:byte(i + 1) >= 0x80 and str:byte(i + 1) <= 0xBF) and
               (str:byte(i + 2) >= 0x80 and str:byte(i + 2) <= 0xBF) then
            -- Start of a 3-byte UTF-8 character
            return false
        elseif (c >= 0xF0 and c <= 0xF4) and (i + 3 <= len) and
               (str:byte(i + 1) >= 0x80 and str:byte(i + 1) <= 0xBF) and
               (str:byte(i + 2) >= 0x80 and str:byte(i + 2) <= 0xBF) and
               (str:byte(i + 3) >= 0x80 and str:byte(i + 3) <= 0xBF) then
            -- Start of a 4-byte UTF-8 character
            return false
        else
            -- If the byte is above 0x7F and doesn't fit UTF-8 patterns, assume CP1252 or ISO-8859-1
            i = i + 1
        end
    end
    return true
end

function to_utf8(str)
    local result = ""
    for i = 1, #str do
        local c = str:byte(i)
        if c < 128 then
            result = result .. string.char(c)
        elseif c >= 128 and c <= 255 then
            result = result .. string.char(0xC0 + math.floor(c / 64), 0x80 + (c % 64))
        end
    end
    return result
end


function detect_charset_convert(tag, timestamp, record)

    raw_string = record["message"]

    if is_cp1252_or_iso8859_1(raw_string) then 
        record["message"] = to_utf8(raw_string)
        return 2, timestamp, record
    else
        return 0, timestamp, record
    end 
       

 end

function filter_big_log(tag, timestamp, record)
    local record_size = 0

    for key, value in pairs(record) do
        --record_size = record_size + #key + #value
         record_size = record_size + #key + #(tostring(value))
    end

    if record_size > 409600  then
        -- If the log is larger than 400KB, filter it out
        return -1, 0, 0
    else
       -- local new_record = record
       record["record_bytesize"] = record_size

       -- return 2, timestamp, new_record
       return 2, timestamp, record
    end
end

function fix_cef_trx_log(tag, timestamp, record)

    --record["message"] = record["msg1"] .. "<trx " .. string.gsub(string.gsub(record["trx_msg"], '=', ':'), '"', '') .. "/trx>" .. record["msg2"]
    record["message"] = record["msg1"] .. string.gsub(string.gsub(record["trx_msg"], '=', ':'), '"', '')  .. record["msg2"]
    record["msg1"] = nil
    record["trx_msg"] = nil
    record["msg2"] = nil

    return 2, timestamp, record
end

function fix_cef_trx_log_v2(tag, timestamp, record)

    --record["message"] = record["msg1"] .. "<trx " .. string.gsub(string.gsub(record["trx_msg"], '=', ':'), '"', '') .. "/trx>" .. record["msg2"]
    --record["message"] = record["msg1"] .. string.gsub(string.gsub(record["msg"], '=', ':'), '"', '')  .. record["msg2"]
    record["message"] = record["msg1"] .. record["msg2"]
    record["msg"] = string.gsub(string.gsub(record["msg"], '=', ':'), '"', '')
    record["msg1"] = nil
    --record["msg"] = nil
    record["msg2"] = nil

    return 2, timestamp, record
end

-- Mappings
MAPPINGS = {
    act = "deviceAction",
    app = "applicationProtocol",
    c6a1 = "deviceCustomIPv6Address1",
    c6a1Label = "deviceCustomIPv6Address1Label",
    c6a2 = "deviceCustomIPv6Address2",
    c6a2Label = "deviceCustomIPv6Address2Label",
    c6a3 = "deviceCustomIPv6Address3",
    c6a3Label = "deviceCustomIPv6Address3Label",
    c6a4 = "deviceCustomIPv6Address4",
    c6a4Label = "deviceCustomIPv6Address4Label",
    cat = "deviceEventCategory",
    cfp1 = "deviceCustomFloatingPoint1",
    cfp1Label = "deviceCustomFloatingPoint1Label",
    cfp2 = "deviceCustomFloatingPoint2",
    cfp2Label = "deviceCustomFloatingPoint2Label",
    cfp3 = "deviceCustomFloatingPoint3",
    cfp3Label = "deviceCustomFloatingPoint3Label",
    cfp4 = "deviceCustomFloatingPoint4",
    cfp4Label = "deviceCustomFloatingPoint4Label",
    cn1 = "deviceCustomNumber1",
    cn1Label = "deviceCustomNumber1Label",
    cn2 = "deviceCustomNumber2",
    cn2Label = "deviceCustomNumber2Label",
    cn3 = "deviceCustomNumber3",
    cn3Label = "deviceCustomNumber3Label",
    cnt = "baseEventCount",
    cs1 = "deviceCustomString1",
    cs1Label = "deviceCustomString1Label",
    cs2 = "deviceCustomString2",
    cs2Label = "deviceCustomString2Label",
    cs3 = "deviceCustomString3",
    cs3Label = "deviceCustomString3Label",
    cs4 = "deviceCustomString4",
    cs4Label = "deviceCustomString4Label",
    cs5 = "deviceCustomString5",
    cs5Label = "deviceCustomString5Label",
    cs6 = "deviceCustomString6",
    cs6Label = "deviceCustomString6Label",
    dhost = "destinationHostName",
    dmac = "destinationMacAddress",
    dntdom = "destinationNtDomain",
    dpid = "destinationProcessId",
    dpriv = "destinationUserPrivileges",
    dproc = "destinationProcessName",
    dpt = "destinationPort",
    dst = "destinationAddress",
    duid = "destinationUserId",
    duser = "destinationUserName",
    dvc = "deviceAddress",
    dvchost = "deviceHostName",
    dvcpid = "deviceProcessId",
    ["end"] = "endTime",  -- 'end' is a reserved keyword in Lua
    fname = "fileName",
    fsize = "fileSize",
    ["in"] = "bytesIn",  -- 'in' is a reserved keyword in Lua
    msg = "message",
    out = "bytesOut",
    outcome = "eventOutcome",
    proto = "transportProtocol",
    request = "requestUrl",
    rt = "deviceReceiptTime",
    shost = "sourceHostName",
    smac = "sourceMacAddress",
    sntdom = "sourceNtDomain",
    spid = "sourceProcessId",
    spriv = "sourceUserPrivileges",
    sproc = "sourceProcessName",
    spt = "sourcePort",
    src = "sourceAddress",
    start = "startTime",
    suid = "sourceUserId",
    suser = "sourceUserName",
    ahost = "agentHost",
    art = "agentReceiptTime",
    at = "agentType",
    aid = "agentId",
    _cefVer = "cefVersion",
    agt = "agentAddress",
    av = "agentVersion",
    atz = "agentTimeZone",
    dtz = "destinationTimeZone",
    slong = "sourceLongitude",
    slat = "sourceLatitude",
    dlong = "destinationLongitude",
    dlat = "destinationLatitude",
    catdt = "categoryDeviceType",
    mrt = "managerReceiptTime",
    amac = "agentMacAddress"
}

-- Simplified pattern for key-value pairs
KEY_VALUE_PATTERN = "(%w+)=(%S+)"

function parse_cef_extension(text)
    local record = {}

    for key, value in text:gmatch(KEY_VALUE_PATTERN) do
           key = MAPPINGS[key] or key
           record[key] = value
    end

    return record
end

function parse_cef_extensionv2(text)
    local record = {}
    local key, value = "", ""
    local inValue = false

    for part in string.gmatch(text, "%S+") do
        if string.find(part, "=") then
            if inValue then
                record[key] = value:match("^%s*(.-)%s*$")
            end
            local split = {}
            key, value = part:match("([^=]+)=(.*)")
            inValue = true
        elseif inValue then
            -- value = value .. " " .. part
	    value = value and (value .. " " .. part) or part
        end
    end

    -- Don't forget to add the last pair
    if inValue then
        record[key] = value:match("^%s*(.-)%s*$")
    end

    return record
end




function cef_extension(tag, timestamp, record)

    local cef_extension_table = {}



    for key, value in pairs(parse_cef_extensionv2(record["cef_extension"])) do
        cef_extension_table[key] = value
    end


  
    record["cef_extension"] = nil

    for key, value in pairs(cef_extension_table) do
	  --  Add this for mapping
	  key = MAPPINGS[key] or key
	  --  End of path
          record[key] = value
    end

    return 2, timestamp, record
end


function append_ts(tag, timestamp, record)
	new_record = record
	new_record["ts"] = string.format("%d.%09d", timestamp["sec"], timestamp["nsec"])

	return 2, timestamp, new_record
end
