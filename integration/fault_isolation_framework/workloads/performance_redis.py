# Copyright 2026 The HuaTuo Authors. Licensed under the Apache License, Version 2.0.
"""Real Redis writes and scheduled BGSAVE with observable fork witnesses."""
import hashlib,json,math,threading,time
from pathlib import Path
from .redis_protocol import command,pipeline,payload,info
from ..core.util import require,wait_for


def completed_fork(before,after,old_mtime,new_mtime):
    complete = new_mtime > old_mtime and after.get('rdb_bgsave_in_progress') == '0' and after.get('rdb_last_bgsave_status') == 'ok' and int(after.get('latest_fork_usec', '0')) > 0
    if 'total_forks' in before and 'total_forks' in after:
        complete = complete and int(after['total_forks']) > int(before['total_forks'])
    return complete


class RedisFixture:
    def __init__(self,owner,port,bind):
        self.owner=owner;self.data=dict(forks=[],errors=[],redis_binary=dict(path=owner.a.redis_server,sha256=hashlib.sha256(Path(owner.a.redis_server).read_bytes()).hexdigest()),keys=owner.a.redis_keys,value_bytes=owner.a.redis_value_bytes);self.thread=None;self.stop=threading.Event()
        self.directory=owner.out/'redis-data';self.directory.mkdir()
        scripts=Path(__file__).parent/'services'
        args=['--network','host','--memory','256m','--memory-swap','256m',
              '-v',str(scripts)+':/fixture:ro','-v',str(self.directory)+':/data']
        for root in ('/usr','/lib','/lib64'):args+=['-v',root+':'+root+':ro']
        self.target=owner.environment.launch(args,['/usr/bin/python3','/fixture/redis_service.py',owner.a.redis_server,bind,str(port)])
        self.target.update(id='neighbor-redis',role='neighbor',kind='redis',keys=owner.a.redis_keys,value_bytes=owner.a.redis_value_bytes)
        self.url=self.target['url']
        wait_for('Redis PING',lambda:command(self.url,'PING')==b'PONG',timeout=15)
        body=payload(owner.a.redis_value_bytes)
        for begin in range(0,owner.a.redis_keys,16):
            replies=pipeline(self.url,[('SET','huatuo:perf:key:%d'%n,body) for n in range(begin,min(begin+16,owner.a.redis_keys))])
            require(all(reply==b'OK' for reply in replies),'Redis seed failed')
        command(self.url,'DEL','huatuo:perf:work-count')
        self.data['before']=info(self.url)
        self.target['oom_before']=(self.target['cgroup']/'memory.failcnt').read_text().strip()
        owner.evidence.register('neighbor-redis-business.log','business_log')
        owner.evidence.register('redis.json','redis_workload',format='json')

    def start(self,start,duration):
        interval=self.owner.a.redis_fork_interval
        if not interval:return
        begin=start+self.owner.a.warmup;end=start+duration
        self.data['planned_forks']=math.ceil((end-begin)/interval)
        def loop():
            due=begin
            try:
                while due<end-1e-8:
                    if self.stop.wait(max(0,due-time.monotonic())):return
                    before=info(self.url)
                    require(before.get('rdb_bgsave_in_progress')=='0','previous Redis BGSAVE still active at next scheduled fork')
                    path=self.directory/'dump.rdb'
                    old_mtime=path.stat().st_mtime_ns if path.exists() else 0
                    row=dict(scheduled=due,time=time.monotonic(),epoch=time.time(),forks_before=before.get('total_forks'),rdb_mtime_before=old_mtime)
                    answer=command(self.url,'BGSAVE')
                    require(answer==b'Background saving started','Redis did not acknowledge BGSAVE')
                    children=Path('/proc')/str(self.target['pid'])/'task'/str(self.target['pid'])/'children'
                    try:row['child_pids_observed']=[int(pid) for pid in children.read_text().split()]
                    except FileNotFoundError:row['child_pids_observed']=[]
                    def saved():
                        after=info(self.url)
                        mtime=path.stat().st_mtime_ns if path.exists() else 0
                        return after if completed_fork(before,after,old_mtime,mtime) else None
                    after=wait_for('actual completed Redis BGSAVE',saved,timeout=min(interval,10))
                    row.update(completed=True,completed_at=time.monotonic(),forks_after=after.get('total_forks'),
                               latest_fork_usec=after['latest_fork_usec'],rdb_last_cow_size=after.get('rdb_last_cow_size'),rdb_mtime_after=path.stat().st_mtime_ns)
                    self.data['forks'].append(row)
                    due+=interval
            except Exception as exc:self.data['errors'].append(repr(exc))
        self.thread=threading.Thread(target=loop,daemon=True);self.thread.start()

    def finish(self,rows):
        self.close()
        after=info(self.url);self.data['after']=after
        counter=command(self.url,'GET','huatuo:perf:work-count')
        self.data['work_count']=int(counter or b'0')
        expected=sum(r['ok'] for r in rows if r['target']==self.target['id'])
        require(self.data['work_count']==expected,'Redis server/client request counter mismatch')
        require(command(self.url,'PING')==b'PONG','Redis unavailable after trial')
        require(not self.data['errors'],'Redis fork schedule failed: '+repr(self.data['errors']))
        if self.owner.a.redis_fork_interval:
            require(len(self.data['forks'])==self.data['planned_forks'],'Redis scheduled forks were not all observed')
            require(after.get('rdb_bgsave_in_progress')=='0' and after.get('rdb_last_bgsave_status')=='ok','Redis BGSAVE did not complete successfully')
            if 'total_forks' in after and 'total_forks' in self.data['before']:
                require(int(after['total_forks'])-int(self.data['before']['total_forks'])>=len(self.data['forks']),'Redis fork counters disagree')
            require((self.directory/'dump.rdb').is_file(),'Redis RDB output missing')

    def close(self):
        self.stop.set()
        if self.thread:
            self.thread.join(8)
            require(not self.thread.is_alive(),'Redis fork controller did not stop')

    def save(self):
        (self.owner.out/'redis.json').write_text(json.dumps(self.data,indent=2)+'\n')
        for p in self.directory.iterdir():
            if p.is_file():self.owner.evidence.register(str(p.relative_to(self.owner.out)),'redis_rdb',format='binary')
