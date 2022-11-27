

#include <iostream>
#include <arm_acle.h>


int main() {


    uint64_t val =0;
   // int z = __rndr(&val);


    uint64_t r = __arm_rsr64("ID_AA64ISAR0_EL1");

    std::cout << std::hex << r <<std::endl;

}