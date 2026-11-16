package native

// Builtins use the same parser and callback API as imported scripts.
const luaHTTPScript = `
local b = require 'backend'
local ready, sent, response = false, false, ''
function wa_lua_on_handshake_cb(ctx)
 if ready then return true end
 if not sent then
  local host = b.get_address_host(ctx)
  if b.get_address_type(ctx) == b.ADDRESS.IPV6 then host = '['..host..']' end
  local target = host..':'..b.get_address_port(ctx)
  local auth = ''
  if settings.username ~= '' then
   auth = 'Proxy-Authorization: Basic '..crypto.base64.encode(settings.username..':'..settings.password)..'\r\n'
  end
  b.write(ctx, 'CONNECT '..target..' HTTP/1.1\r\nHost: '..target..'\r\n'..auth..'\r\n')
  sent = true
 end
 return false
end
function wa_lua_on_read_cb(ctx, data)
 if ready then return b.RESULT.SUCCESS, data end
 response = response..data
 if #response > 65536 then return b.RESULT.ERROR end
 local start, finish = string.find(response, '\r\n\r\n', 1, true)
 if not start then return b.RESULT.HANDSHAKE end
 if not string.match(response, '^HTTP/%d%.%d 200[ \r]') then return b.RESULT.ERROR end
 ready = true
 local tail = response:sub(finish + 1)
 response = ''
 return b.RESULT.HANDSHAKE, tail
end
`
const luaTrojanScript = `
local b = require 'backend'
local n = require 'network'
local digest = crypto.digest.new('SHA224')
digest:update(settings.password)
local authentication = digest:final()
function wa_lua_on_handshake_cb(ctx)
 local kind = b.get_address_type(ctx)
 local address = b.get_address_bytes(ctx)
 if kind == b.ADDRESS.DOMAIN then
  address = b.get_address_host(ctx)
  address = string.char(#address)..address
 end
 b.write(ctx, authentication..'\r\n'..string.char(1, kind)..address..n.htons(b.get_address_port(ctx))..'\r\n')
 return true
end
`
const luaLightswordScript = `
local b = require 'backend'
local n = require 'network'
local info = crypto.cipher_info(settings.method)
local key = string.rep(settings.password, math.ceil(info.key / #settings.password)):sub(1, info.key)
local sent, ready = false, false
local encryptor, decryptor, headSize
local pending = ''
local parser, decoded = nil, ''
local parsedEnd = 0
function wa_lua_on_handshake_cb(ctx)
 if ready then return true end
 if sent then return false end
 local kind = b.get_address_type(ctx)
 local address = b.get_address_bytes(ctx)
 if kind == b.ADDRESS.DOMAIN then
  address = b.get_address_host(ctx)
  address = string.char(#address)..address
 end
 address = address..n.htons(b.get_address_port(ctx))
 headSize = #address + 4
 local iv = crypto.rand.bytes(info.iv)
 local padding = crypto.rand.bytes(math.random(0,255))
 local header = string.char(5,#padding)..padding..string.char(5,1,0,kind)..address
 local headerCipher = crypto.encrypt.new(settings.method,key,iv)
 encryptor = crypto.encrypt.new(settings.method,key,iv)
 b.write(ctx,iv..headerCipher:update(header)..headerCipher:final())
 sent = true
 return false
end
function wa_lua_on_read_cb(ctx,data)
 if ready then return b.RESULT.SUCCESS,decryptor:update(data) end
 pending = pending..data
 if #pending > 65536 then return b.RESULT.ERROR end
 if #pending < info.iv + 1 then return b.RESULT.HANDSHAKE end
 local iv = pending:sub(1,info.iv)
 if not parser then
  parser = crypto.decrypt.new(settings.method,key,iv)
  parsedEnd = info.iv
 end
 decoded = decoded..parser:update(pending:sub(parsedEnd+1))
 parsedEnd = #pending
 local required = 1 + decoded:byte(1) + headSize
 if #decoded < required then return b.RESULT.HANDSHAKE end
 decryptor = crypto.decrypt.new(settings.method,key,iv)
 local tail = decryptor:update(pending:sub(info.iv+required+1))
 parser,decoded = nil,''
 pending,ready = '',true
 return b.RESULT.HANDSHAKE,tail
end
function wa_lua_on_write_cb(ctx,data)
 return b.RESULT.SUCCESS,encryptor:update(data)
end
`
