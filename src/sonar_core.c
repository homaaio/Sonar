
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <math.h>

double scan_entropy(const char *path){
    FILE *f=fopen(path,"rb");if(!f)return -1.0;
    uint64_t freq[256]={0},total=0;uint8_t buf[65536];size_t n;
    while((n=fread(buf,1,sizeof(buf),f))>0){for(size_t i=0;i<n;i++)freq[buf[i]]++;total+=n;}
    fclose(f);if(total==0)return 0.0;
    double e=0.0;
    for(int i=0;i<256;i++){if(!freq[i])continue;double p=(double)freq[i]/(double)total;e-=p*log2(p);}
    return e;
}
double scan_nullratio(const char *p){
    FILE *f=fopen(p,"rb");if(!f)return -1.0;
    uint64_t z=0,t=0;uint8_t buf[65536];size_t n;
    while((n=fread(buf,1,sizeof(buf),f))>0){for(size_t i=0;i<n;i++)if(!buf[i])z++;t+=n;}
    fclose(f);return t==0?0.0:(double)z/(double)t;
}
double scan_ascii_ratio(const char *p){
    FILE *f=fopen(p,"rb");if(!f)return -1.0;
    uint64_t a=0,t=0;uint8_t buf[65536];size_t n;
    while((n=fread(buf,1,sizeof(buf),f))>0){for(size_t i=0;i<n;i++)if(buf[i]>=0x20&&buf[i]<=0x7E)a++;t+=n;}
    fclose(f);return t==0?0.0:(double)a/(double)t;
}
uint32_t calc_crc32(const char *p){
    static uint32_t tbl[256];static int ready=0;
    if(!ready){for(uint32_t i=0;i<256;i++){uint32_t c=i;for(int k=0;k<8;k++)c=(c&1)?(0xEDB88320u^(c>>1)):(c>>1);tbl[i]=c;}ready=1;}
    FILE *f=fopen(p,"rb");if(!f)return 0;
    uint32_t crc=0xFFFFFFFFu;uint8_t buf[65536];size_t n;
    while((n=fread(buf,1,sizeof(buf),f))>0)for(size_t i=0;i<n;i++)crc=tbl[(crc^buf[i])&0xFF]^(crc>>8);
    fclose(f);return crc^0xFFFFFFFFu;
}
void byte_histogram(const char *p, uint64_t *out){
    memset(out,0,256*sizeof(uint64_t));
    FILE *f=fopen(p,"rb");if(!f)return;
    uint8_t buf[65536];size_t n;
    while((n=fread(buf,1,sizeof(buf),f))>0)for(size_t i=0;i<n;i++)out[buf[i]]++;
    fclose(f);
}
double lsb_randomness(const uint8_t *pixels, int64_t count){
    if(count<2)return 0.0;
    int64_t diff=0;
    for(int64_t i=0;i+1<count;i++)diff+=((pixels[i]^pixels[i+1])&1);
    return (double)diff/(double)(count-1);
}
