#pragma once
#include <vector>
#include <cstdint>
#include <cstddef>
namespace scanmath {
struct Total {size_t parent; uint64_t bytes=0; bool complete=false;};
inline void aggregate(std::vector<Total>& nodes){
 for(size_t i=nodes.size();i-->0;){auto p=nodes[i].parent;if(p==size_t(-1))continue;
 if(p>=i){nodes[i].complete=false;continue;}
 nodes[p].bytes+=nodes[i].bytes;nodes[p].complete=nodes[p].complete&&nodes[i].complete;
 }
}
}
