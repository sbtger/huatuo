// Copyright 2026 The HuaTuo Authors
// Licensed under the Apache License, Version 2.0.
import com.sun.net.httpserver.HttpServer;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.*;
import java.util.concurrent.Executors;
import java.lang.management.ManagementFactory;

public class ResidentKV {
    static class Record {
        final int key;final byte[] value;final Map<String,Object> labels;final List<Object> children;
        Record(int key){this.key=key;value=new byte[key%10==0?65536:1024];Arrays.fill(value,(byte)(97+key%26));labels=new HashMap<>();labels.put("kind",key%10);labels.put("key",key);children=new ArrayList<>();children.add(new int[]{key,key+1});children.add(new HashMap<>(labels));}
    }
    static final ArrayList<Record> records=new ArrayList<>();
    static final Record[] churn=new Record[64];
    static final MessageDigest datasetHash;
    static {try{datasetHash=MessageDigest.getInstance("SHA-256");}catch(Exception error){throw new RuntimeException(error);}}
    static final long[] counts=new long[3];
    static Map<String,String> query(String raw){Map<String,String> out=new HashMap<>();if(raw!=null)for(String part:raw.split("&")){String[] pieces=part.split("=",2);if(pieces.length==2)out.put(pieces[0],pieces[1]);}return out;}
    static String stats(){
        StringBuilder gc=new StringBuilder();
        for(var bean:ManagementFactory.getGarbageCollectorMXBeans()){if(gc.length()>0)gc.append(',');gc.append("{\"name\":\"").append(bean.getName()).append("\",\"collections\":").append(bean.getCollectionCount()).append(",\"collection_wall_ms\":").append(bean.getCollectionTime()).append('}');}
        var heap=ManagementFactory.getMemoryMXBean().getHeapMemoryUsage();
        String digest;try{digest=HexFormat.of().formatHex(((MessageDigest)datasetHash.clone()).digest());}catch(Exception error){throw new RuntimeException(error);}
        return "{\"dataset_sha256\":\""+digest+"\",\"records\":"+records.size()+",\"churn_slots\":64,\"runtime\":\"HotSpot "+System.getProperty("java.version")+"\",\"operations\":{\"GET\":"+counts[0]+",\"SET\":"+counts[1]+",\"DELETE\":"+counts[2]+"},\"gc\":{\"cpu_seconds\":null,\"collectors\":["+gc+"],\"heap_used_bytes\":"+heap.getUsed()+",\"heap_committed_bytes\":"+heap.getCommitted()+",\"heap_max_bytes\":"+heap.getMax()+"},\"small_bytes\":1024,\"large_bytes\":65536,\"large_every\":10}";
    }
    public static void main(String[] args) throws Exception {
        for(int i=0;i<64;i++)churn[i]=new Record(i);
        int port=Integer.parseInt(System.getenv().getOrDefault("HUATUO_TEST_PORT","30000"));
        var server=HttpServer.create(new InetSocketAddress("0.0.0.0",port),64);server.setExecutor(Executors.newFixedThreadPool(8));
        server.createContext("/",exchange->{
            synchronized(records){try{
                var q=query(exchange.getRequestURI().getRawQuery());String path=exchange.getRequestURI().getPath();String body;
                if(path.equals("/fill")&&exchange.getRequestMethod().equals("POST")){
                    int n=Integer.parseInt(q.getOrDefault("records","-1"));if(n<records.size()||n>1000000)throw new IllegalArgumentException("bounded grow-only FILL required");
                    while(records.size()<n){Record record=new Record(records.size());String line=record.key+":"+record.value.length+":"+HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(record.value))+"\n";datasetHash.update(line.getBytes(StandardCharsets.UTF_8));records.add(record);}body=stats();
                }else if(path.equals("/stats")){body=stats();}
                else if(path.equals("/op")&&records.size()>=1024){
                    long ordinal=Long.parseLong(q.get("ordinal")),seed=Long.parseLong(q.get("seed"));long mixed=((ordinal+seed)*1103515245L+12345)&0x7fffffffL;
                    int kind=0,key=(int)(mixed%Math.min(records.size(),1024));Record value=records.get(key);
                    if(mixed%10>=6){key=(int)(mixed%64);kind=mixed%10>=9?2:1;if(kind==2)churn[key]=null;churn[key]=new Record(key);value=churn[key];}
                    counts[kind]++;body=ordinal+"|"+new String[]{"GET","SET","DELETE"}[kind]+"|"+key+"|"+HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(value.value))+"\n";
                }else throw new IllegalArgumentException("unknown operation or unfilled store");
                byte[] bytes=body.getBytes(StandardCharsets.UTF_8);exchange.sendResponseHeaders(200,bytes.length);exchange.getResponseBody().write(bytes);
            }catch(Exception error){byte[] bytes=error.toString().getBytes(StandardCharsets.UTF_8);exchange.sendResponseHeaders(400,bytes.length);exchange.getResponseBody().write(bytes);}finally{exchange.close();}}
        });
        server.start();System.out.println("{\"pid\":"+ProcessHandle.current().pid()+",\"url\":\"http://127.0.0.1:"+port+"\",\"language\":\"java\"}");
    }
}
