-- Trace the ROM execution
-- Press A button repeatedly and observe memory

local frame_count = 0
local press_count = 0
local done = false

function onFrame()
    frame_count = frame_count + 1

    -- Wait a few frames for init
    if frame_count < 30 then
        return
    end

    -- Read EWRAM to see what's there
    if frame_count == 30 then
        console:log("=== Frame 30 ===")
        -- Read EWRAM start
        local ewram_start = emu:read32(0x02000000)
        console:log(string.format("EWRAM[0..4] = %08x", ewram_start))

        -- Read IWRAM for the counter
        local counter = emu:read32(0x0300009c)
        console:log(string.format("counter = %d", counter))

        -- Read DMA registers
        for i = 0, 3 do
            local base = 0x040000B0 + i * 12
            local sad = emu:read32(base)
            local dad = emu:read32(base + 4)
            local cnt = emu:read32(base + 8)
            console:log(string.format("DMA%d: SAD=%08x DAD=%08x CNT=%08x", i, sad, dad, cnt))
        end

        -- Read current screen row (just text)
        -- Tile data at VRAM 0x06000000
    end

    -- Press A button occasionally to add character
    if frame_count % 20 == 0 and press_count < 3 then
        emu:addKey(0)  -- A
    elseif frame_count % 20 == 5 and press_count < 3 then
        emu:clearKey(0)
        press_count = press_count + 1
        local counter = emu:read32(0x0300009c)
        console:log(string.format("After press %d: counter = %d", press_count, counter))
        -- Dump buffer
        local line = "Buffer: "
        for i = 0, 9 do
            line = line .. string.format("%04x ", emu:read16(0x030000a0 + i*2))
        end
        console:log(line)
    end
end

callbacks:add("frame", onFrame)
console:log("Trace script loaded")
