/* Test-only measurement hooks for pinned wrk2. Native pacing is unchanged. */
#include "hdr_histogram.h"
#define BENCH_HISTS (36 + 128 * 2)
static __thread struct hdr_histogram *bench_hist[BENCH_HISTS];
static __thread uint64_t bench_errors[12], bench_counts[12], bench_overflow;
static int script_wrk_bench_record(lua_State *L) {
    int phase=luaL_checkinteger(L,1),op=luaL_checkinteger(L,2),window=luaL_checkinteger(L,3);
    int64_t values[3]={luaL_checknumber(L,4),luaL_checknumber(L,5),luaL_checknumber(L,6)};
    bool ok=lua_toboolean(L,7);
    if(phase<0||phase>3||op<0||op>2||window<0||window>=128)return luaL_error(L,"bounded metric index exceeded");
    int slot=phase*3+op;bench_counts[slot]++;if(!ok)bench_errors[slot]++;
    for(int k=0;k<3;k++) {
        int index=slot*3+k;
        if(!bench_hist[index])hdr_init(1,60000000,3,&bench_hist[index]);
        if(values[k]<0||!hdr_record_value(bench_hist[index],values[k]?values[k]:1))bench_overflow++;
    }
    for(int k=0;k<2;k++) {
        int index=36+window*2+k;
        if(!bench_hist[index])hdr_init(1,60000000,3,&bench_hist[index]);
        int64_t value=values[k==0?0:2];
        if(value<0||!hdr_record_value(bench_hist[index],value?value:1))bench_overflow++;
    }
    return 0;
}
static int script_wrk_bench_dump(lua_State *L) {
    const char *path=luaL_checkstring(L,1);FILE *out=fopen(path,"wx");
    if(!out)return luaL_error(L,"cannot create metrics artifact");
    fprintf(out,"H,1,60000000,3,%llu\n",(unsigned long long)bench_overflow);
    for(int i=0;i<12;i++)fprintf(out,"C,%d,%llu,%llu\n",i,(unsigned long long)bench_counts[i],(unsigned long long)bench_errors[i]);
    for(int i=0;i<BENCH_HISTS;i++)if(bench_hist[i]) {
        struct hdr_iter iterator;hdr_iter_init(&iterator,bench_hist[i]);
        while(hdr_iter_next(&iterator))if(iterator.count_at_index)
            fprintf(out,"B,%d,%lld,%lld\n",i,(long long)iterator.highest_equivalent_value,(long long)iterator.count_at_index);
        free(bench_hist[i]);bench_hist[i]=NULL;
    }
    if(fclose(out))return luaL_error(L,"metrics artifact close failed");
    return 0;
}
static void script_bench_finish(lua_State *L) {
    lua_getglobal(L,"bench_finish");if(lua_isfunction(L,-1))lua_call(L,0,0);else lua_pop(L,1);
}
static void script_bench_failure(lua_State *L,const char *kind,connection *c,uint64_t now) {
    lua_getglobal(L,"bench_failure");if(!lua_isfunction(L,-1)){lua_pop(L,1);return;}
    lua_pushstring(L,kind);lua_pushlstring(L,c->request?c->request:"",c->request?c->length:0);
    if(c->request && c->thread_start && c->throughput>0)lua_pushnumber(L,c->thread_start+(c->complete_at_last_batch_start/c->throughput));else lua_pushnil(L);
    if(c->request && c->actual_latency_start)lua_pushnumber(L,c->actual_latency_start);else lua_pushnil(L);
    lua_pushnumber(L,now);lua_call(L,5,0);
}
