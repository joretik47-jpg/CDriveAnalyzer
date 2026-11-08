#include "../src/scan_math.h"
#include <cassert>
int main(){
 using scanmath::Total;
 std::vector<Total> a{{size_t(-1),10,true},{0,20,true},{1,30,true},{0,40,true}};
 scanmath::aggregate(a);assert(a[0].bytes==100&&a[1].bytes==50&&a[0].complete);
 std::vector<Total> b{{size_t(-1),10,true},{0,0,false},{0,20,true}};
 scanmath::aggregate(b);assert(b[0].bytes==30&&!b[0].complete&&b[2].complete);
 std::vector<Total> c{{size_t(-1),0,true},{0,1,true},{1,0,false}};
 scanmath::aggregate(c);assert(!c[0].complete&&!c[1].complete);
 std::vector<Total> empty;scanmath::aggregate(empty);
}
