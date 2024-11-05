/**
 */


#include "sha256.h"

SHAState *makeState()
{
    SHAState *state = (SHAState *) malloc(sizeof(SHAState));
    *state = (SHAState) {
        .h = {0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au, 0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u},
        .pcount = 0,
    };
    return state;
}

void freeState(SHAState *state)
{
    free(state);
}

void addLastEightBytes(SHAState *state)
{
    int n = state->len*BBITS;
    for (int i = BLOCK_SIZE-1; i>=BLOCK_SIZE-BBITS; i--){
        if (n!=0){
            state->pending[i] = n%256;
            n = n>>8;
        }
        else{
            state->pending[i] = 0;
        }
    }
}

word rotate( word val, int bits )
{
    return ((val >> bits) | (val << (WORD_LEN - bits)));
}

word Sigma0( word a )
{
    return (rotate(a,2) ^ rotate(a,13) ^ rotate(a,22));
}

word Sigma1( word a )
{
    return (rotate(a,6) ^ rotate(a,11) ^ rotate(a,25));
}

word ChFunction( word e, word f, word g )
{
    return (( e & f ) ^ ( ~ e & g ));
}

word MaFunction( word a, word b, word c )
{
    return (( a & b ) ^ ( a & c ) ^ ( b & c ));
}

void computeRound(SHAState *state, word w[BLOCK_SIZE], int n)
{
    word newE;
    word newA;

    word parsedValue = ChFunction(state->h[4], state->h[5], state->h[6]) + state->h[7] + w[n] + constant_k[n];
    //printf("%d - %x %x %x %x\n", n, ChFunction(state->h[4], state->h[5], state->h[6]), state->h[7] , w[n] , constant_k[n]);
    //printf("%d - %x\n", n, parsedValue);
    parsedValue += Sigma1(state->h[4]);
    //printf("%d - %x\n", n, parsedValue);
    newE = parsedValue + state->h[3];
    parsedValue += MaFunction(state->h[0], state->h[1], state->h[2]);
    //printf("%d - %x\n", n, parsedValue);
    parsedValue += Sigma0(state->h[0]);
    //printf("%d - %x\n", n, parsedValue);
    newA = parsedValue;

    state->h[7] = state->h[6];
    state->h[6] = state->h[5];
    state->h[5] = state->h[4];
    state->h[4] = newE;
    state->h[3] = state->h[2];
    state->h[2] = state->h[1];
    state->h[1] = state->h[0];
    state->h[0] = newA;
    //printf("%d - %x %x %x\n", n,state->h[0], state->h[2], state->h[4]);
    //printf("\n");
    state->pcount++;
}

void extendMessage( byte const pending[ BLOCK_SIZE ], word w[ BLOCK_SIZE ] )
{
    for (int i = 0; i<BLOCK_SIZE; i+=4){
        for (int j = i; j<i+4; j++){
            w[i/4] = ((w[i/4]<<8) | pending[j]);
        }
    }

    for (int i = INIT_W_LEN; i<BLOCK_SIZE; i++){
        w[i] = (rotate(w[i-INIT_W_LEN+1], 7) ^ rotate(w[i-INIT_W_LEN+1], 18) ^ (w[i-INIT_W_LEN+1] >> 3)) + (rotate(w[i-2], 17) ^ rotate(w[i-2], 19) ^ (w[i-2] >> 10));
        w[i] += w[i-7] + w[i-INIT_W_LEN];
    }

}

void compression( SHAState *state )
{
    word w[BLOCK_SIZE];
    extendMessage(state->pending, w);

    word first_h[HASH_WORDS];
    for (int i = 0; i<HASH_WORDS; i++){
        first_h[i] = state->h[i];
    }

    for (int i = 0; i<BLOCK_SIZE; i++){
        computeRound(state, w, i);
    }

    for (int i = 0; i<HASH_WORDS; i++){
        state->h[i] += first_h[i];
    }

}


void update( SHAState *state, const byte data[], int len )
{
    if (state->foundLen == 0){
        state->len = len;
        state->foundLen = 1;
    }
    for (int i = 0; i<=len-BLOCK_SIZE; i+=64){
        for (int j = 0; j<BLOCK_SIZE; j++){
            state->pending[j] = data[i+j];
        }
        compression(state);
    }

    int j = 0;
    for (int i = len - (len%BLOCK_SIZE) ; i<len; i++){
        state->pending[j] = data[i];
        j++;
    }
    state->pcount = j;

    //printf("%d - %02x\n", j, state->pending[j]);
}

void digest( SHAState *state, word hash[ HASH_WORDS ] )
{

    state->pending[state->pcount] = 0x80;
    if (state->pcount+1 > BLOCK_SIZE-BBITS){
        for (int i = state->pcount+1; i<BLOCK_SIZE; i++){
            state->pending[i] = 0;
        }
        update(state, state->pending, BLOCK_SIZE);
        for (int i = 0; i<BLOCK_SIZE; i++){
            state->pending[i] = 0;
        }
        addLastEightBytes(state);
        update(state, state->pending, BLOCK_SIZE);
    }
    else{
        for (int i = state->pcount+1; i<BLOCK_SIZE-BBITS; i++){
            state->pending[i] = 0;
        }
        addLastEightBytes(state);
        update(state, state->pending, BLOCK_SIZE);
    }

    for (int i = 0; i<HASH_WORDS; i++){
        hash[i] = state->h[i];
    }
}

// int main(){
//     SHAState state = {
//         .h = {0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au, 0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u},
//         .pcount = 0,
//     };
//     word w[BLOCK_SIZE];
//     w[0] = 0x54657374;
//     computeRound(&state, w, 0);
//     return(0);
// }