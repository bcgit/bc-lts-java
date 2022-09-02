//
// Created on 24/5/2022.
//

#ifndef CORENATIVE_CIPHERTEXTEXCEPTION_H
#define CORENATIVE_CIPHERTEXTEXCEPTION_H

#include <stdexcept>
#include <string>
namespace exceptions {
    class CipherTextException : public std::runtime_error {

    public:
        CipherTextException(const std::string& msg);
    };
}


#endif //CORENATIVE_CIPHERTEXTEXCEPTION_H
