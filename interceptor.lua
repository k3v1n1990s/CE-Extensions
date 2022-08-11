--{$lua}
--generateCodeInjectionScript(script: Tstrings, address: string, farjmp: boolean) - Adds a default codeinjection script to the given script
local function generateScript(script, sender)
    local address = getMemoryViewForm().DisassemblerView.SelectedAddress
    local address_string = getNameFromAddress(address)
    script:clear()
	generateCodeInjectionScript(script, address_string, true)
    --replace script //place your code here to your code
    
    script.Text = [[
loadlibrary(luaclient-i386.dll)
luacall(openLuaServer('CELUASERVER'))
CELUA_ServerName:
db 'CELUASERVER',0
LUA_FUNCNAME:
db 'hook_internal(parameter)',0
]]..string.gsub(script.Text, '//place your code here', string.format([[
pushad
pushfd
push %s
push esp
push LUA_FUNCNAME
call CELUA_ExecuteFunction
add esp, 0x4
popfd
popad
]], address_string))
    
end
unregisterAutoAssemblerTemplate('intercepter')
registerAutoAssemblerTemplate('intercepter', function(script, sender)
    generateScript(script, sender)
end,'Ctrl+Q')

function hex(n)
    return string.format("0x%.8x", n)
end

function hook_internal(reg)
    --pushad
    --pushfd
    --push address
    --push esp
    local ctx = {}
    ctx.eip = readPointer(reg)
    ctx.eflag = readPointer(reg+4)
    ctx.edi = readPointer(reg+8)
    ctx.esi = readPointer(reg+12)
    ctx.ebp = readPointer(reg+16)
    ctx.esp = readPointer(reg+20)
    ctx.ebx = readPointer(reg+24)
    ctx.edx = readPointer(reg+28)
    ctx.ecx = readPointer(reg+32)
    ctx.eax = readPointer(reg+36)
    ctx.log = function()
        print(string.format("eip: %s", hex(ctx.eip)))
        print(string.format("eflag: %s", hex(ctx.eflag)))
        print(string.format("edi: %s", hex(ctx.edi)))
        print(string.format("esi: %s", hex(ctx.esi)))
        print(string.format("ebp: %s", hex(ctx.ebp)))
        print(string.format("esp: %s", hex(ctx.esp)))
        print(string.format("ebx: %s", hex(ctx.ebx)))
        print(string.format("edx: %s", hex(ctx.edx)))
        print(string.format("ecx: %s", hex(ctx.ecx)))
        print(string.format("eax: %s", hex(ctx.eax)))
    end
    hook(ctx)
end
