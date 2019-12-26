#include<stdlib.h>
#include<pbc/pbc.h>
#include "keymanager.h"

struct KeyManager {
    element_t alpha1;
    element_t alpha2;
};

size_t getKeyManagerSize() {
    return sizeof(struct KeyManager);
}

void initializeKeyManager(struct KeyManager* manager, pairing_t pairing) {
    element_init_Zr(manager -> alpha1, pairing);
    element_init_Zr(manager -> alpha2, pairing);
    element_random(manager -> alpha1);
    element_random(manager -> alpha2);
}

void getPowerAlpha1(element_t result, element_t input,struct KeyManager* manager) {
    element_pow_zn(result, input, manager -> alpha1);
}

void getPowerAlpha2(element_t result, element_t input,struct KeyManager* manager) {
    element_pow_zn(result, input, manager -> alpha2);
}
