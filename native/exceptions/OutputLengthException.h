//
// Created  on 24/5/2022.
//

#ifndef CORENATIVE_OUTPUTLENGTHEXCEPTION_H
#define CORENATIVE_OUTPUTLENGTHEXCEPTION_H

#include <exception>
#include <stdexcept>

namespace exceptions {
    class OutputLengthException: public std::runtime_error {

    public:
        OutputLengthException(const std::string& msg);
    };
}


#endif //CORENATIVE_OUTPUTLENGTHEXCEPTION_H
