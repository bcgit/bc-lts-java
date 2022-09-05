//
// Created  on 24/5/2022.
//

#include "CipherTextException.h"

#include <stdexcept>


exceptions::CipherTextException::CipherTextException(const std::string &msg) : std::runtime_error(msg) {

}
