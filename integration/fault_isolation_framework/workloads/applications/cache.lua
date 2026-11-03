-- Fixed cache-v1 body oracle. Requires documented measurement hooks, pipeline=1.
local ffi=require('ffi')
local bit=require('bit')
ffi.cdef[[ typedef void *gzFile; gzFile gzopen(const char*,const char*); int gzwrite(gzFile,const void*,unsigned); int gzclose(gzFile); ]]
local z=ffi.load('libz.so.1')
local threads={};local index=0;local sequence=0;local values={};local gz=nil
local records,seed,thread_count,warmup,baseline,hold,recovery,start_epoch,trace_start,trace_end,root,diagnostic
local metrics_begin=0
raw_count=0;body_errors=0;trace_overflow=0;checked=0;raw_bytes=0
function setup(thread)
  thread:set('bench_index',index);index=index+1;table.insert(threads,thread)
end
local source=debug.getinfo(1,'S').source
local recipe=dofile(string.match(source,'^@(.*/)[^/]+$')..'cache_recipe.lua')
local function value(key)
  local kind=key%26 .. ':'..(key%10==0 and 'large' or 'small')
  if not values[kind] then values[kind]=string.rep(string.char(97+key%26),key%10==0 and 65536 or 1024) end
  return values[kind]
end
local function raw(row)
  if raw_bytes+#row>134217728 then trace_overflow=trace_overflow+1;return end
  if z.gzwrite(gz,row,#row)~=#row then error('trace write failed') end
  raw_bytes=raw_bytes+#row;raw_count=raw_count+1
end
function init(args)
  records=tonumber(args[1]);seed=tonumber(args[2]);thread_count=tonumber(args[3]);warmup=tonumber(args[4]);baseline=tonumber(args[5]);hold=tonumber(args[6]);recovery=tonumber(args[7]);start_epoch=tonumber(args[8]);trace_start=tonumber(args[9]);trace_end=tonumber(args[10]);root=args[11];diagnostic=tonumber(args[12]) or 0
  gz=z.gzopen(root..'/trace-'..bench_index..'.jsonl.gz','wb1');if gz==nil then error('cannot create trace') end
end
function request()
  sequence=sequence+1
  local ordinal=sequence*thread_count+bench_index+1
  local op,key=recipe(ordinal,seed,records);local delay=(diagnostic==1 and ordinal%20==0) and 20 or 0
  return wrk.format(op=='SET' and 'PUT' or op,'/cache/'..key..'?ordinal='..ordinal..'&seed='..seed..'&delay_ms='..delay,{['Content-Type']='application/octet-stream'},op=='SET' and value(key) or nil)
end
local function phase(planned)
  local elapsed=planned/1000000-start_epoch
  if elapsed<warmup then return 0 elseif elapsed<warmup+baseline then return 1 elseif elapsed<warmup+baseline+hold then return 2 else return 3 end
end
function response(status,headers,body,planned,sent,ended,original_request)
  if not planned then error('stock wrk2 lacks required native timeline hooks') end
  local normalized={};for k,v in pairs(headers) do normalized[string.lower(k)]=v end
  local ordinal=tonumber(string.match(original_request,'ordinal=(%d+)'));local response_ordinal=tonumber(normalized['x-bench-ordinal']);local reported=normalized['x-bench-operation'];local key=tonumber(normalized['x-bench-key'])
  local op,wanted=nil,nil
  if ordinal then op,wanted=recipe(ordinal,seed,records) end
  local ok=status==200 and ordinal~=nil and response_ordinal==ordinal and reported==op and key==wanted and body==value(wanted)
  checked=checked+1;if not ok then body_errors=body_errors+1 end
  local p=phase(planned);local elapsed=planned/1000000-start_epoch;local window=math.floor(math.max(0,elapsed)/5)
  if p>=0 and p<=3 and window<128 then
    wrk.bench_record(p,op=='GET' and 0 or (op=='SET' and 1 or 2),window,ended-planned,ended-sent,sent-planned,ok)
  else trace_overflow=trace_overflow+1 end
  local epoch=planned/1000000
  if not ok or (epoch>=trace_start and epoch<=trace_end) then
    raw(string.format('{"ordinal":%d,"operation":"%s","key":%d,"scheduled_epoch":%.6f,"sent_epoch":%.6f,"ended_epoch":%.6f,"status":%d,"ok":%s,"body_bytes":%d,"diagnostic_delay_ms":%d}\n',ordinal or -1,op or 'UNKNOWN',key or -1,planned/1000000,sent/1000000,ended/1000000,status,ok and 'true' or 'false',#body,(diagnostic==1 and ordinal and ordinal%20==0) and 20 or 0))
  end
end
function bench_failure(kind,request,planned,sent,ended)
  local ordinal=tonumber(string.match(request,'ordinal=(%d+)'))
  local op,key='UNKNOWN',-1;if ordinal then op,key=recipe(ordinal,seed,records) end
  local expected=planned and string.format('%.6f',planned/1000000) or 'null'
  local actual=sent and string.format('%.6f',sent/1000000) or 'null'
  raw(string.format('{"ordinal":%d,"operation":"%s","key":%d,"transport_error":"%s","scheduled_epoch":%s,"sent_epoch":%s,"ended_epoch":%.6f,"ok":false}\n',ordinal or -1,op,key,kind,expected,actual,ended/1000000))
end
function bench_finish()
  wrk.bench_dump(root..'/hist-'..bench_index..'.csv')
  if z.gzclose(gz)~=0 then error('trace close failed') end
end
function done(summary,latency,requests)
  local bad,overflow,count,raw_total=0,0,0,0
  for _,thread in ipairs(threads) do bad=bad+thread:get('body_errors');overflow=overflow+thread:get('trace_overflow');count=count+thread:get('checked');raw_total=raw_total+thread:get('raw_count') end
  io.write(string.format('BENCH_JSON {"requests":%d,"checked":%d,"body_errors":%d,"trace_overflow":%d,"raw_rows":%d,"duration_us":%d,"timeouts":%d,"connect_errors":%d,"read_errors":%d,"write_errors":%d,"status_errors":%d}\n',summary.requests,count,bad,overflow,raw_total,summary.duration,summary.errors.timeout,summary.errors.connect,summary.errors.read,summary.errors.write,summary.errors.status))
end
