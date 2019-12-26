#include<pbc/pbc.h>

struct KeyManager;

size_t getKeyManagerSize();
void initializeKeyManager(struct KeyManager* manager, pairing_t pairing);
void getPowerAlpha1(element_t result, element_t input, struct KeyManager* manager);
void getPowerAlpha2(element_t result, element_t input, struct KeyManager* manager);
