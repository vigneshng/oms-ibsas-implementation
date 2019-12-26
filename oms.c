#include <stdio.h>
#include <string.h>
#include <openssl/sha.h>
#include <pbc/pbc.h>

struct SecretKey {
    element_t s;
    element_t t;
    element_t u;
};

struct PublicKey {
    element_t S;
    element_t T;
    element_t U;
};

// Compares 2 public keys
int compare(struct PublicKey p, struct PublicKey q)  
{   
    if(element_cmp(p.S,q.S)==0) {
         if(element_cmp(p.T,q.T)==0) {
             return element_cmp(p.U,q.U);
         }
         else return element_cmp(p.T,q.T);
    }
    else return element_cmp(p.S,q.S);
} 

struct Parameters {
    pairing_t pairing;
    element_t g;
};

struct Signature {
    element_t Q;
    element_t R;
};

//Takes a message as input and returns hash of the message and converts into element_t
void sha256(char message[], element_t hash) {
    unsigned char obuf[32];
    SHA256(message, strlen(message), obuf);
    element_from_hash(hash, obuf, 32);
}

//Initializes the different parameters
void initializeParameters(struct Parameters* paramStruct) {
    pbc_param_t param;
    pbc_param_init_a_gen(param,160,512);
    pairing_init_pbc_param(paramStruct -> pairing, param);
    element_init_G1(paramStruct -> g, paramStruct -> pairing);
    element_random(paramStruct -> g);
}

//Initializes the public key and secret key for a user
void initializeKeys(struct PublicKey* pk, struct SecretKey* sk, struct Parameters param) {
    element_init_Zr(sk -> s, param.pairing);
    element_init_Zr(sk -> t, param.pairing);
    element_init_Zr(sk -> u, param.pairing);
    element_random(sk -> s);
    element_random(sk -> t);
    element_random(sk -> u);
    element_init_G1(pk -> S, param.pairing);
    element_init_G1(pk -> T, param.pairing);
    element_init_G1(pk -> U, param.pairing);
    element_pp_t g_pp;
    element_pp_init(g_pp, param.g);
    element_pp_pow_zn(pk -> S, sk -> s, g_pp); 
    element_pp_pow_zn(pk -> T, sk -> t, g_pp); 
    element_pp_pow_zn(pk -> U, sk -> u, g_pp); 
    element_pp_clear(g_pp);
}

//Verifies the signature based on the message and list of public key of the prior signers
int verify(char message[], struct Signature signature, struct PublicKey signers[], 
    int numSigners, struct Parameters param) {
    if(numSigners==0) return 1;
    for (int i=0;i<numSigners;i++) {
        for(int j=i+1;j<numSigners;j++) {
            if(compare(signers[i],signers[j])==0) return 0;
        }
    }
    element_t Q,g,h,R,J;
    element_t temp1,temp2,temp3,temp4;
    element_t result1, result2, result3, result4;
    element_init_G1(Q, param.pairing);
    element_init_G1(g, param.pairing);
    element_init_G1(h, param.pairing);
    element_init_G1(R, param.pairing);
    element_init_G1(J, param.pairing);
    element_init_G1(temp1, param.pairing);
    element_init_G1(temp2, param.pairing);
    element_init_G1(temp3, param.pairing);
    element_init_G1(temp4, param.pairing);
    element_init_GT(result1, param.pairing);
    element_init_GT(result2, param.pairing);
    element_init_GT(result3, param.pairing);
    element_init_GT(result4, param.pairing);
    element_set(Q, signature.Q);
    element_set(R, signature.R);
    element_set(g, param.g);
    pairing_apply(result1, Q, g,param.pairing);
    element_set1(temp1);
    for(int j=0;j<numSigners;j++) {
        element_mul_zn(temp1,temp1,signers[j].S);
        element_set_si(J,j+1);
        element_pow_zn(temp2, signers[j].U, J);
        element_mul_zn(temp3, temp2, signers[j].T);
    }
    sha256(message,temp4);
    pairing_apply(result2, temp4, temp1, param.pairing);
    pairing_apply(result3, temp3, R, param.pairing);
    element_mul_zn(result4, result2, result3);
    if(element_cmp(result1,result4)) {
        return 0;
    }
    else return 1;
}

//Signs the message using the secret key and the signature produced by prior signers
void sign(struct SecretKey sk, char message[], struct Signature* signature,
     struct PublicKey signers[], int numSigners, struct Parameters param) {
    if(verify(message,*signature,signers,numSigners,param)==0) {
        signature = NULL;
        return;
    }
    element_t r,R,X,Y,Q,h,J;
    element_t temp1, temp2, temp3, temp4;
    element_init_Zr(r, param.pairing);
    element_init_G1(R, param.pairing);
    element_init_G1(X, param.pairing);
    element_init_G1(Y, param.pairing);
    element_init_G1(Q, param.pairing);
    element_init_G1(h, param.pairing);
    element_init_G1(J, param.pairing);
    element_init_G1(temp1, param.pairing);
    element_init_G1(temp2, param.pairing);
    element_init_G1(temp3, param.pairing);
    element_init_G1(temp4, param.pairing);
    element_random(r);
    element_pow_zn(temp1,param.g, r);
    element_mul_zn(R,signature -> R, temp1);
    element_pow_zn(temp1, R, sk.t);
    element_set_si(J,numSigners+1);
    element_mul_zn(temp4, J, sk.u);
    element_pow_zn(temp2, R, temp4);
    element_mul_zn(X,temp2 , temp1);
    element_set1(temp4);
    for(int j=0;j< numSigners; j++) {
        element_set_si(J,j+1);
        element_pow_zn(temp1, signers[j].U, J);
        element_mul_zn(temp2, temp1, signers[j].T);
        element_mul_zn(temp3, temp1, temp2);
        element_mul_zn(temp4, temp4, temp3);
    }
    element_pow_zn(Y,temp4,r);
    element_mul_zn(temp1, X, Y);
    sha256(message, h);
    element_pow_zn(temp3, h, sk.s);
    element_mul_zn(temp2, temp1, signature -> Q);
    element_mul_zn(Q,temp2, temp3);
    element_set(signature -> Q, Q);
    element_set(signature -> R, R);
}

int main()
{
    unsigned char ibuf[] = "Hello";
    struct Parameters param;
    initializeParameters(&param);
    struct PublicKey pk[5];
    struct SecretKey sk[5];
    struct Signature signature;
    element_init_G1(signature.Q, param.pairing);
    element_init_G1(signature.R, param.pairing);
    element_set1(signature.Q);
    element_set1(signature.R);
    for(int i=0; i< 5; i++) {
        initializeKeys(&pk[i],&sk[i],param);
        sign(sk[i],ibuf,&signature,pk,i,param);
    }
    printf("%d\n",verify(ibuf,signature,pk,5,param));

    return 0;
}
