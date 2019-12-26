#include<stdio.h>
#include<string.h>
#include <openssl/sha.h>
#include <pbc/pbc.h>

struct SecretKey {
    element_t s1;
    element_t s2;
};

struct KeyMessagePair {
    char* publicKey;
    char* message;
};

struct Parameters {
    pairing_t pairing;
    element_t g;
    element_t galpha1;
    element_t galpha2;
    struct KeyManager* manager;
};

struct Signature {
    element_t sigma1;
    element_t sigma2;
    element_t sigma3;
};

//Hashes the message using SHA256 and converts into an element_t
void sha256(char message[], element_t hash) {
    unsigned char obuf[32];
    SHA256(message, strlen(message), obuf);
    element_from_hash(hash, obuf, 32);
}

//Initializes the parameters required for IBSAS construction
void initializeParameters(struct Parameters* paramStruct) {
    pbc_param_t param;
    pbc_param_init_a_gen(param,160,512);
    pairing_init_pbc_param(paramStruct -> pairing, param);
    element_init_G1(paramStruct -> g, paramStruct -> pairing);
    element_init_G1(paramStruct -> galpha1, paramStruct -> pairing);
    element_init_G1(paramStruct -> galpha2, paramStruct -> pairing);
    element_random(paramStruct -> g);
    paramStruct -> manager = (struct KeyManager*)malloc(getKeyManagerSize());
    initializeKeyManager(paramStruct -> manager, paramStruct -> pairing);
    getPowerAlpha1(paramStruct->galpha1,paramStruct->g,paramStruct->manager);
    getPowerAlpha2(paramStruct->galpha2,paramStruct->g,paramStruct->manager); 
}

//Initializes a small list of PublicKey Message Pair
void initializeKeyMessagePair(struct KeyMessagePair* list) {
    list[0].publicKey = "First user";
    list[0].message = "First message";
    list[1].publicKey = "Second user";
    list[1].message = "Second message";
    list[2].publicKey = "Third user";
    list[2].message = "Third message";
}

//Calls the key authority and gets the secret key based on the given public key
void initializeSecretKey(struct SecretKey* sk, struct KeyMessagePair* pk,struct Parameters param) {
    element_t h1,h2;
    element_init_G1(h1, param.pairing);
    element_init_G1(h2, param.pairing);
    element_init_G1(sk -> s1, param.pairing);
    element_init_G1(sk -> s2, param.pairing);
    sha256(pk -> publicKey, h1);
    sha256(pk -> publicKey, h2);
    getPowerAlpha1(sk -> s1, h1, param.manager);
    getPowerAlpha2(sk -> s2, h2, param.manager); 
}

//Verifies the given signature and the list of PublicKey and Message Pair
int verify(struct Signature signature, struct KeyMessagePair L[], int numSigners,
    struct Parameters param) {
    if(numSigners == 0) return 1;
    for (int i=0;i<numSigners;i++) {
        for(int j=i+1;j<numSigners;j++) {
            if(strcmp(L[i].publicKey,L[j].publicKey)==0) return 0;
        }
    }
    element_t temp1,temp2,temp3,temp4,h1,h2,h3;
    element_t result1,result2,result3,result4,result5;
    element_init_Zr(h3, param.pairing);
    element_init_G1(temp1,param.pairing);
    element_init_G1(temp2,param.pairing);
    element_init_G1(temp3,param.pairing);
    element_init_G1(temp4,param.pairing);
    element_init_G1(h1,param.pairing);
    element_init_G1(h2,param.pairing);
    element_init_GT(result1,param.pairing);
    element_init_GT(result2,param.pairing);
    element_init_GT(result3,param.pairing);
    element_init_GT(result4,param.pairing);
    element_init_GT(result5,param.pairing);
    pairing_apply(result1,signature.sigma1,param.g,param.pairing);
    pairing_apply(result2,signature.sigma2,signature.sigma3,param.pairing);
    element_set1(temp1);
    element_set1(temp2);
    for(int i=0;i<numSigners;i++) {
        sha256(L[i].publicKey,h2);
        element_mul_zn(temp1,temp1,h2);
        sha256(L[i].publicKey,h1);
        char tempString[80];
        strcpy(tempString, L[i].publicKey);
        strcat(tempString, L[i].message);
        sha256(tempString,h3);
        element_pow_zn(temp3,h1,h3);
        element_mul_zn(temp2,temp2,temp3);
    }
    pairing_apply(result3,temp1,param.galpha2,param.pairing);
    pairing_apply(result4,temp2,param.galpha1,param.pairing);
    element_mul_zn(result5,result3,result4);
    element_mul_zn(result5,result5,result2);
    if(element_cmp(result1,result5)) {
        return 0;
    }
    else return 1;
}

//Signs the current message with current secret,public keys and the prior list of KeyMessage pairs
void sign(struct SecretKey sk, struct Signature* signature, struct KeyMessagePair currentPair,
    struct KeyMessagePair L[], int numSigners, struct Parameters param) {
    if(verify(*signature, L, numSigners, param) == 0) {
        signature = NULL;
        return;
    }
    char tempString[80];
    strcpy(tempString, currentPair.publicKey);
    strcat(tempString, currentPair.message);
    element_t r,x,h,sigma1,sigma2,sigma3;
    element_t temp1, temp2, temp3,temp4;
    element_init_Zr(r, param.pairing);
    element_init_Zr(x, param.pairing);
    element_init_Zr(h, param.pairing);
    element_init_G1(sigma1, param.pairing);
    element_init_G1(sigma2, param.pairing);
    element_init_G1(sigma3, param.pairing);
    element_init_G1(temp1, param.pairing);
    element_init_G1(temp2, param.pairing);
    element_init_G1(temp3, param.pairing);
    element_init_G1(temp4, param.pairing);
    element_random(r);
    element_random(x);
    element_set(sigma1,signature -> sigma1);
    element_set(sigma2,signature -> sigma2);
    element_set(sigma3,signature -> sigma3);
    sha256(tempString, h);
    element_pow_zn(temp3,param.g,x);
    element_pow_zn(temp2, param.g, r);
    element_mul_zn(signature->sigma3, temp3, sigma3);
    element_mul_zn(signature->sigma2, temp2, sigma2);
    element_pow_zn(temp3, sigma3, r);
    element_pow_zn(temp2, signature->sigma2, x);
    element_mul_zn(temp4,temp2,temp3);
    element_mul_zn(temp1, temp4, sigma1);
    element_mul_zn(temp2, temp1, sk.s2);
    element_pow_zn(temp3, sk.s1, h);
    element_mul_zn(signature->sigma1,temp2,temp3);
} 

int main() {
    struct Parameters param;
    initializeParameters(&param);
    struct KeyMessagePair L[3];
    struct SecretKey sk[3];
    struct Signature signature;
    element_init_G1(signature.sigma1, param.pairing);
    element_init_G1(signature.sigma2, param.pairing);
    element_init_G1(signature.sigma3, param.pairing);
    element_set1(signature.sigma1);
    element_set1(signature.sigma2);
    element_set1(signature.sigma3);
    initializeKeyMessagePair(L);
    for(int i=0; i< 3; i++) {
        initializeSecretKey(&sk[i],&L[i],param);
        sign(sk[i],&signature,L[i],L,i,param);
    }
    printf("%d\n",verify(signature,L,3,param));
}
