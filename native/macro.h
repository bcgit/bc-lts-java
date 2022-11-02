#ifndef MACRO_H
#define MACRO_H

#include "iostream"


//
// abortXX functions are intended to cause the JVM to exit.
//

#define abortIfNot( condition, msg) if (! (condition)) {              \
        std::cerr << #msg << " " << __FUNCTION__ << std::flush <<  std::endl; \
        abort();   \
    } \

#define abortIf( condition, msg) if ( (condition)) {              \
        std::cerr << #msg << " " << __FUNCTION__ << std::flush <<  std::endl; \
        abort();   \
    } \

#define abortIfNegative( i) if ( (i < 0)) {              \
        std::cerr << #i << " are less than zero in " << __FUNCTION__ << std::flush <<  std::endl; \
        abort();   \
    } \

#endif