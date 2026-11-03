// Copyright 2026. Licensed under the Apache License, Version 2.0.
package bench;

import java.lang.management.*;
import java.security.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicLong;
import org.springframework.boot.*;
import org.springframework.boot.autoconfigure.*;
import org.springframework.web.bind.annotation.*;
import org.springframework.http.*;
import org.springframework.web.server.ResponseStatusException;

@SpringBootApplication
@RestController
public class Application {
    record Record(int key, byte[] value, Map<String,String> labels, List<int[]> children) {}
    final ConcurrentHashMap<Integer,Record> cache = new ConcurrentHashMap<>();
    final Object[] stripes = new Object[256];
    final AtomicLong gets=new AtomicLong(), sets=new AtomicLong(), deletes=new AtomicLong(), inflight=new AtomicLong(), maximum=new AtomicLong();
    boolean frozen;
    volatile long datasetSeed=-1;
    Application() { Arrays.setAll(stripes, i -> new Object()); }
    static ResponseStatusException bad() { return new ResponseStatusException(HttpStatus.BAD_REQUEST); }
    static Record make(int key) { byte[] v=new byte[key%10==0?65536:1024]; Arrays.fill(v,(byte)(97+key%26)); return new Record(key,v,Map.of("kind","cache","key",Integer.toString(key)),List.of(new int[]{key,key+1},new int[]{key%7})); }
    static void positive(long n) { if(n<0) throw bad(); }
    @PostMapping("/fill") synchronized Map<String,Object> fill(@RequestParam int records,@RequestParam long seed) {
        positive(seed); if(frozen || records<1024 || records>1000000 || records<cache.size()) throw bad();
        if(datasetSeed!=-1 && datasetSeed!=seed) throw bad(); datasetSeed=seed;
        for(int i=cache.size();i<records;i++) cache.put(i,make(i)); return Map.of("records",cache.size());
    }
    @PostMapping("/freeze") synchronized Map<String,Object> freeze() { frozen=true; return Map.of("frozen",true,"records",cache.size()); }
    @RequestMapping(value="/cache/{key}",method={RequestMethod.GET,RequestMethod.PUT,RequestMethod.DELETE})
    ResponseEntity<byte[]> access(@PathVariable int key,@RequestParam long ordinal,@RequestParam long seed,@RequestParam(defaultValue="0") int delay_ms,@RequestBody(required=false) byte[] body,jakarta.servlet.http.HttpServletRequest request) throws InterruptedException {
        positive(ordinal); positive(seed); if(seed!=datasetSeed) throw bad(); if(key<0 || delay_ms<0 || delay_ms>100 || (delay_ms!=0&&!"1".equals(System.getenv("APP_DIAGNOSTIC")))) throw bad();
        long n=inflight.incrementAndGet(); maximum.accumulateAndGet(n,Math::max);
        try {
            if(delay_ms>0) Thread.sleep(delay_ms);
            String method=request.getMethod(); Record value;
            synchronized(stripes[key%stripes.length]) {
                value=cache.get(key); if(value==null) throw new ResponseStatusException(HttpStatus.NOT_FOUND);
                if(method.equals("PUT")) { Record next=make(key); if(!Arrays.equals(body,next.value())) throw bad(); cache.put(key,next); value=next; sets.incrementAndGet(); }
                else if(method.equals("DELETE")) { cache.remove(key); cache.put(key,make(key)); deletes.incrementAndGet(); }
                else gets.incrementAndGet();
            }
            return ResponseEntity.ok().contentType(MediaType.APPLICATION_OCTET_STREAM).header("X-Bench-Ordinal",Long.toString(ordinal)).header("X-Bench-Operation",method.equals("PUT")?"SET":method).header("X-Bench-Key",Integer.toString(key)).body(value.value());
        } finally { inflight.decrementAndGet(); }
    }
    static String sha(byte[] bytes) { try { return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes)); } catch(Exception e) { throw new IllegalStateException(e); } }
    @GetMapping("/stats") Map<String,Object> stats(@RequestParam(defaultValue="0") int verify) {
        if(verify!=0&&verify!=1) throw bad();
        Map<String,Object> out=new LinkedHashMap<>(); int count=cache.size(); long large=(count+9L)/10;
        out.put("records",count); out.put("live_count",count); out.put("value_bytes",large*65536+(count-large)*1024); out.put("operations",Map.of("GET",gets.get(),"SET",sets.get(),"DELETE",deletes.get())); out.put("inflight",inflight.get()); out.put("max_inflight",maximum.get()); out.put("runtime",Map.of("framework","spring-boot-3.4.5","java",System.getProperty("java.version"),"pid",ProcessHandle.current().pid(),"workers",32));
        var heap=ManagementFactory.getMemoryMXBean().getHeapMemoryUsage(); out.put("heap_used_bytes",heap.getUsed()); out.put("heap_committed_bytes",heap.getCommitted()); out.put("heap_max_bytes",heap.getMax());
        long collections=0,time=0; for(var gc:ManagementFactory.getGarbageCollectorMXBeans()) { collections+=Math.max(0,gc.getCollectionCount()); time+=Math.max(0,gc.getCollectionTime()); } Map<String,Object> gcStats=new LinkedHashMap<>(); gcStats.put("collections",collections); gcStats.put("collection_wall_ms",time); gcStats.put("cpu_ms",null); out.put("gc",gcStats);
        if(verify==1) {
            try {
                MessageDigest digest=MessageDigest.getInstance("SHA-256");
                for(int key=0;key<count;key++) {
                    synchronized(stripes[key%256]) {
                        var r=cache.get(key);
                        if(r!=null) digest.update((key+":"+r.value().length+":"+sha(r.value())+"\n").getBytes(StandardCharsets.UTF_8));
                    }
                }
                out.put("dataset_sha256",HexFormat.of().formatHex(digest.digest()));
            } catch(NoSuchAlgorithmException e) { throw new IllegalStateException(e); }
        }
        return out;
    }
    public static void main(String[] args) { SpringApplication app=new SpringApplication(Application.class); app.setDefaultProperties(Map.of("server.address","0.0.0.0","server.port",System.getenv().getOrDefault("HUATUO_TEST_PORT","30000"),"server.tomcat.threads.max","32","server.tomcat.threads.min-spare","4","server.tomcat.accept-count","128")); app.run(args); }
}
