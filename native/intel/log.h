#ifndef LOG_H
#define LOG_H

#include <string.h>
#include <iostream>



#ifdef LLCYCLE
[[maybe_unused]] void llog_new(std::string msg, void *ptr) {
    std::cout <<"New: " << msg <<" "<< (long)ptr << std::endl;
}

[[maybe_unused]] void llog_delete(std::string msg, void *ptr) {
    std::cout <<"Delete: " << msg << " " << (long)ptr << std::endl;
}

#define LNEW(msg,ptr) llog_new(msg,ptr);
#define LDELETE(msg,ptr) llog_delete(msg,ptr);

#else

#define LNEW(msg,ptr)
#define LDELETE(msg,ptr)
#endif

#endif // LOG_H
