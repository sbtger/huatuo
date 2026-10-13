// Copyright 2026 The HuaTuo Authors
// Licensed under the Apache License, Version 2.0.
import com.sun.net.httpserver.HttpServer;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.HexFormat;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.nio.channels.FileChannel;
import java.nio.file.StandardOpenOption;
import sun.misc.Unsafe;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicLong;

public class SnapshotBusiness {
    static long seq,total;
    static final AtomicLong ticks=new AtomicLong();
    static synchronized String state(){return "{\"seq\":"+seq+",\"total\":"+total+",\"ticks\":"+ticks.get()+",\"completed\":"+completed.get()+"}";}
    static volatile String phase="warmup";
    static final AtomicLong completed=new AtomicLong();
    static final byte[] template=new byte[128*1024];
    static byte[][] retained;
    public static void main(String[] args) throws Exception {
        if(args.length>1)Class.forName(args[1]);
        java.lang.reflect.Field field=Unsafe.class.getDeclaredField("theUnsafe");field.setAccessible(true);
        Unsafe cleaner=(Unsafe)field.get(null);
        Files.createDirectories(Path.of("/tmp"));
        int heap=args.length>0?Integer.parseInt(args[0]):32;
        retained=new byte[heap][1024*1024];
        for(int i=0;i<template.length;i++)template[i]=(byte)(i%251);
        Thread background=new Thread(()->{
            ArrayList<ByteBuffer> chunks=new ArrayList<>();
            ArrayList<Path> files=new ArrayList<>();
            for(;;){try{
                int target=Integer.parseInt(Files.readString(Path.of("/control/target_mb")).trim());
                while(chunks.size()<target){
                    Path file=Files.createTempFile("memsnapshot-pressure-",".bin");
                    try(FileChannel channel=FileChannel.open(file,StandardOpenOption.READ,StandardOpenOption.WRITE)){
                        ByteBuffer b=channel.map(FileChannel.MapMode.READ_WRITE,0,1<<20);
                        for(int p=0;p<b.capacity();p+=4096)b.put(p,(byte)1);
                        chunks.add(b);files.add(file);
                    }
                }
                while(chunks.size()>target){cleaner.invokeCleaner(chunks.remove(chunks.size()-1));Files.delete(files.remove(files.size()-1));}
                ticks.incrementAndGet();Thread.sleep(100);
            }catch(Exception e){e.printStackTrace();try{Thread.sleep(100);}catch(Exception ignored){}}}
        });background.setDaemon(true);background.start();
        HttpServer server=HttpServer.create(new InetSocketAddress("127.0.0.1",0),64);
        server.setExecutor(Executors.newFixedThreadPool(16));
        server.createContext("/state",exchange->{byte[] body=state().getBytes(StandardCharsets.UTF_8);exchange.sendResponseHeaders(200,body.length);exchange.getResponseBody().write(body);exchange.close();});
        server.createContext("/txn",exchange->{
            synchronized(SnapshotBusiness.class){
                long n=Long.parseLong(exchange.getRequestURI().getQuery().substring(4));
                if(!exchange.getRequestMethod().equals("POST")||n!=seq+1){exchange.sendResponseHeaders(409,-1);exchange.close();return;}
                seq=n;total+=n*13;
                byte[] body=state().getBytes(StandardCharsets.UTF_8);exchange.sendResponseHeaders(200,body.length);exchange.getResponseBody().write(body);exchange.close();
            }
        });
        server.createContext("/phase",exchange->{
            byte[] bytes=exchange.getRequestBody().readNBytes(129);
            if(!exchange.getRequestMethod().equals("POST")||bytes.length<1||bytes.length>128){exchange.sendResponseHeaders(400,-1);exchange.close();return;}
            phase=new String(bytes,StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(204,-1);exchange.close();
        });
        server.createContext("/stats",exchange->{
            byte[] body=("{\"completed\":"+completed.get()+"}").getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(200,body.length);exchange.getResponseBody().write(body);exchange.close();
        });
        server.createContext("/work",exchange->{
            try{
                byte[] data=template.clone();
                byte[] extra=new byte[(int)(completed.get()%64)*8192];
                for(int i=0;i<extra.length;i+=4096)extra[i]=1;
                byte[] digest=null;
                for(int i=0;i<4;i++)digest=MessageDigest.getInstance("SHA-256").digest(data);
                byte[] body=(HexFormat.of().formatHex(digest)+"\n").getBytes(StandardCharsets.UTF_8);
                completed.incrementAndGet();
                exchange.getResponseHeaders().set("X-Test-Phase",phase);
                exchange.sendResponseHeaders(200,body.length);exchange.getResponseBody().write(body);
            }catch(Exception error){exchange.sendResponseHeaders(500,-1);}
            finally{exchange.close();}
        });
        server.start();
        System.out.println("{\"pid\":"+ProcessHandle.current().pid()+",\"language\":\"java\",\"runtime\":\""+System.getProperty("java.version")+"\",\"url\":\"http://127.0.0.1:"+server.getAddress().getPort()+"\",\"heap_mib\":"+heap+",\"expected_body\":\"feb1e4409d009e0ec502eaabe321f86b5197a881e9b765252ec8a75d6957596d\\n\"}");
    }
}
