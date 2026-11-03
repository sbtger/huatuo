-- Exact integer cache-v1 recipe shared by workload and cross-runtime checks.
local bit=require('bit')
local function mul32(a,b)
  local low=bit.band(a,65535)*bit.band(b,65535)
  local mid=bit.band(a,65535)*bit.rshift(b,16)+bit.rshift(a,16)*bit.band(b,65535)
  return bit.tobit(low+bit.lshift(bit.tobit(mid),16))
end
local function recipe(ordinal,seed,records)
  local mixed=bit.band(mul32(ordinal+seed,1103515245)+12345,2147483647)
  local op=mixed%100<70 and 'GET' or (mixed%100<90 and 'SET' or 'DELETE')
  local hot=math.max(1,math.min(records-1,math.ceil(records*.2)))
  local draw=(mixed*48271)%2147483647
  local key=math.floor(mixed/100)%100<80 and draw%hot or hot+draw%(records-hot)
  return op,key
end
return recipe
