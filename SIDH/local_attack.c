#include "SIDH.h"
#include "SIDH_internal.h"
#include <memory.h>
#include <stdio.h>
#include <stdlib.h>

#define RETURN_IF_ERROR(c) do { CRYPTO_STATUS x = (c); if (x != CRYPTO_SUCCESS) { return x; } } while (0)

typedef struct {
    unsigned char* pub;
    unsigned char* priv;
    unsigned char* shared;
} kex_data;

void norm_proj(point_proj_t A, f2elm_t x) {
    fp2copy751(A->Z, x);
    fp2inv751_mont(x);
    fp2mul751_mont(A->X, x, x);
}

void blab_digits(bool upper, digit_t* data, unsigned int length) {
    unsigned int i;
    for (i = 0; i < length; ++i) {
        if (upper) {
            printf("%016lX", data[length - i -1]);
        } else {
            printf("%016lx", data[length - i -1]);
        }
    }
}

void blab_felm_t(felm_t data) {
    blab_digits(false, data, 12);
}

void blab_f2elm_t(f2elm_t data) {
    f2elm_t normalized;
    fp2copy751(data, normalized);
    fp2correction751(normalized);
    printf("(");
    blab_felm_t(normalized[0]);
    printf(",");
    blab_felm_t(normalized[1]);
    printf(")");
}

void blab_order(digit_t* data) {
    blab_digits(false, data, 6);
    printf("\n");
}

void blab_point_proj(point_proj_t P) {
    printf("{ X: ");
    blab_f2elm_t(P[0].X);
    printf("\n  Z: ");
    blab_f2elm_t(P[0].Z);
    printf("\n");
}

void blab_point_proj_norm(point_proj_t P) {
    f2elm_t x;
    norm_proj(P, x);

    printf("X/Z = ");
    blab_f2elm_t(x);
    printf("\n");
}

CRYPTO_STATUS alloc_kex_data(kex_data* data, PCurveIsogenyStruct CurveIsogeny) {
    unsigned int pbytes = (CurveIsogeny->pwordbits + 7)/8;   // Number of bytes in a field element 
    unsigned int obytes = (CurveIsogeny->owordbits + 7)/8;   // Number of bytes in an element in [1, order]
        
    data->pub = (unsigned char*)calloc(1, 3*2*pbytes);     // Three elements in GF(p^2)
    data->priv = (unsigned char*)calloc(1, obytes);        // One element in [1, order]  
    data->shared = (unsigned char*)calloc(1, 2*pbytes);    // One element in GF(p^2)  

    return CRYPTO_SUCCESS;
}

CRYPTO_STATUS my_random(unsigned int nbytes, unsigned char* random_array) {
    if (nbytes == 0) return CRYPTO_ERROR;

    unsigned int i;
    for (i = 0; i < nbytes; ++i) {
        random_array[i] = rand();
    }
    return CRYPTO_SUCCESS;
}

CRYPTO_STATUS make_curve(PCurveIsogenyStruct* CurveIsogeny) {
    CurveIsogenyStaticData CurveIsogenyData = CurveIsogeny_SIDHp751;
    *CurveIsogeny = SIDH_curve_allocate(&CurveIsogenyData);
    CRYPTO_STATUS status = SIDH_curve_initialize(*CurveIsogeny, &my_random, &CurveIsogenyData);
    return status;
}

bool compare_f2elm(f2elm_t A, f2elm_t B) {
    f2elm_t ANorm, BNorm;
    fp2copy751(A, ANorm);
    fp2copy751(B, BNorm);
    fp2correction751(ANorm);
    fp2correction751(BNorm);
    unsigned int i;
    for (i = 0; i < NWORDS_FIELD; ++i) {
        if (ANorm[0][i] != BNorm[0][i]) return false;
        if (ANorm[1][i] != BNorm[1][i]) return false;
    }
    return true;
}

static f2elm_t FP2ZERO = {0};

bool compare_point_proj(point_proj_t A, point_proj_t B) {
    return compare_f2elm(A->X, B->X) && compare_f2elm(A->Z, B->Z);
}

CRYPTO_STATUS expect_not_O(point_proj_t A, const char* label) {
    if (compare_f2elm(FP2ZERO, A->Z)) {
        printf("!!! Failure !!!\n");
        printf("=== %s ===\n", label);
        blab_point_proj(A);
        return CRYPTO_ERROR;
    }
    return CRYPTO_SUCCESS;
}

CRYPTO_STATUS expect_O(point_proj_t A, const char* label) {
    if (!compare_f2elm(FP2ZERO, A->Z)) {
        printf("!!! Failure !!!\n");
        printf("=== %s ===\n", label);
        blab_point_proj(A);
        return CRYPTO_ERROR;
    }
    return CRYPTO_SUCCESS;
}

CRYPTO_STATUS expect_point_proj(point_proj_t E, point_proj_t A, const char* label_E, const char* label_A) {
    bool e_is_zero = compare_f2elm(FP2ZERO, E->Z);
    bool a_is_zero = compare_f2elm(FP2ZERO, A->Z);
    if (e_is_zero) {
        if (a_is_zero) {
            return CRYPTO_SUCCESS;
        }
        printf("!!! Failure !!!\n");
        printf("=== %s ===\n", label_E);
        printf("(zero)\n");
        printf("=== %s ===\n", label_A);
        blab_point_proj_norm(A);
        return CRYPTO_ERROR;
    } else if(a_is_zero) {
        printf("!!! Failure !!!\n");
        printf("=== %s ===\n", label_E);
        blab_point_proj_norm(E);
        printf("=== %s ===\n", label_A);
        printf("(zero)\n");
        return CRYPTO_ERROR;
    }

    f2elm_t EX, AX;
    norm_proj(A, AX);
    norm_proj(E, EX);
    if (!compare_f2elm(EX, AX)) {
        printf("!!! Failure !!!\n");
        printf("=== %s ===\n", label_E);
        blab_point_proj_norm(E);
        printf("=== %s ===\n", label_A);
        blab_point_proj_norm(A);
        return CRYPTO_ERROR;
    }
    return CRYPTO_SUCCESS;
}

void ladder2(f2elm_t x, digit_t* m, point_proj_t P, point_proj_t Q, f2elm_t A, unsigned int order_bits, unsigned int order_fullbits, PCurveIsogenyStruct CurveIsogeny)
{ // The Montgomery ladder
  // Inputs: the affine quadratic x-coordinate of a point P on E: B*y^2=x^3+A*x^2+x,
  //         scalar m
  //         curve constant A24 = (A+2)/4
  //         order_bits = subgroup order bitlength
  //         order_fullbits = smallest multiple of 32 larger than the order bitlength
  // Output: Q = m*(x:1)
  // CurveIsogeny must be set up in advance using SIDH_curve_initialize().
    unsigned int bit = 0, owords = NBITS_TO_NWORDS(order_fullbits);
    digit_t mask;
    int i;
    f2elm_t A24, constant, A24num;

    // Initializing with the points (1:0) and (x:1)
    fp2zero751(P->X);
    fpcopy751((digit_t*)CurveIsogeny->Montgomery_one, (digit_t*)P->X[0]);
    fp2zero751(P->Z);

    fp2copy751(x, Q->X);
    fp2zero751(Q->Z);
    fpcopy751((digit_t*)CurveIsogeny->Montgomery_one, (digit_t*)Q->Z[0]);

    fp2zero751(constant);
    fpcopy751((digit_t*)CurveIsogeny->Montgomery_one, constant[0]);
    fp2add751(constant, constant, constant);
    fp2add751(A, constant, A24num);
    fp2div2_751(A24num, A24);
    fp2div2_751(A24, A24);

    for (i = order_fullbits-order_bits; i > 0; i--) {
        mp_shiftl1(m, owords);
    }

    for (i = order_bits; i > 0; i--) {
        bit = (unsigned int)(m[owords-1] >> (RADIX-1));
        mp_shiftl1(m, owords);
        mask = 0-(digit_t)bit;

        swap_points(P, Q, mask);
        xDBLADD(P, Q, x, A24);           // If bit=0 then P <- 2*P and Q <- P+Q,
        swap_points(P, Q, mask);         // else if bit=1 then Q <- 2*Q and P <- P+Q
    }
}

CRYPTO_STATUS tests(PCurveIsogenyStruct CurveIsogeny) {
    {
        f2elm_t A, C;
        point_proj_t G;

        // G <- (PA.x:1)
        fpcopy751(CurveIsogeny->PA, G->X[0]);
        fpzero751(G->X[1]);
        to_mont(G->X[0], G->X[0]);
        fpcopy751(CurveIsogeny->Montgomery_one, G->Z[0]);
        fpzero751(G->Z[1]);

        // Get curve parameters.
        fpcopy751(CurveIsogeny->A, A[0]);
        fpzero751(A[1]);
        fpcopy751(CurveIsogeny->C, C[0]);
        fpzero751(C[1]);
        to_mont(A[0], A[0]);
        to_mont(C[0], C[0]);

        // Check that [2^372]G = O.
        point_proj_t Zero;
        xDBLe(G, Zero, A, C, 371);
        RETURN_IF_ERROR(expect_not_O(Zero, "[2^371]G"));
        xDBLe(G, Zero, A, C, 372);
        RETURN_IF_ERROR(expect_O(Zero, "[2^372]G"));

        point_proj_t Q;
        digit_t Order[MAXWORDS_ORDER];
        Order[372 / 64] = 1LL << (372 % 64);
        ladder2(G->X, Order, Zero, Q, A, CurveIsogeny->oAbits + 1, CurveIsogeny->owordbits, CurveIsogeny);
        RETURN_IF_ERROR(expect_O(Zero, "[2^372]G (ladder2)"));

        memset(Order, 0, sizeof(Order));
        Order[371 / 64] = 1LL << (371 % 64);
        ladder2(G->X, Order, Zero, Q, A, CurveIsogeny->oAbits + 1, CurveIsogeny->owordbits, CurveIsogeny);
        RETURN_IF_ERROR(expect_not_O(Zero, "[2^371]G (ladder2)"));

        memset(Order, 0, sizeof(Order));
        Order[372 / 64] = 1LL << (372 % 64);
        Order[0] = 1LL;
        ladder2(G->X, Order, Zero, Q, A, CurveIsogeny->oAbits + 1, CurveIsogeny->owordbits, CurveIsogeny);
        RETURN_IF_ERROR(expect_not_O(Zero, "[1 + 2^372]G (ladder2)"));

        point_proj_t G2_24, G2_24B;
        xDBLe(G, G2_24, A, C, 24);
        memset(Order, 0, sizeof(Order));
        Order[0] = 1LL << 24;
        ladder2(G->X, Order, G2_24B, Q, A, CurveIsogeny->oAbits + 1, CurveIsogeny->owordbits, CurveIsogeny);
        RETURN_IF_ERROR(expect_point_proj(G2_24, G2_24B, "[2^24]G", "[2^24]G (ladder2)"));
    }

    kex_data bob;
    alloc_kex_data(&bob, CurveIsogeny);
    RETURN_IF_ERROR(KeyGeneration_B(bob.priv, bob.pub, CurveIsogeny));
    f2elm_t xP, xQ, xPQ;
    to_fp2mont(((f2elm_t*)bob.pub)[0], xP);
    to_fp2mont(((f2elm_t*)bob.pub)[1], xQ);
    to_fp2mont(((f2elm_t*)bob.pub)[2], xPQ);

    // Get the Montgomery A parameter. xDBLe wants it in A/C form.
    f2elm_t A, C;
    get_A(xP, xQ, xPQ, A, CurveIsogeny);
    fpcopy751(CurveIsogeny->Montgomery_one, C[0]);
    fpzero751(C[1]);

    point_proj_t phiP;
    fp2copy751(xP, phiP->X);
    fp2zero751(phiP->Z);
    fpcopy751(CurveIsogeny->Montgomery_one, phiP->Z[0]);

    point_proj_t phiQ;
    fp2copy751(xP, phiQ->X);
    fp2zero751(phiQ->Z);
    fpcopy751(CurveIsogeny->Montgomery_one, phiQ->Z[0]);

    {
        point_proj_t Zero;
        xDBLe(phiP, Zero, A, C, 371);
        RETURN_IF_ERROR(expect_not_O(Zero, "[2^371]phi(P_A)"));
        xDBLe(phiP, Zero, A, C, 372);
        RETURN_IF_ERROR(expect_O(Zero, "[2^372]phi(P_A)"));
        xDBLe(phiQ, Zero, A, C, 371);
        RETURN_IF_ERROR(expect_not_O(Zero, "[2^371]phi(Q_A)"));
        xDBLe(phiQ, Zero, A, C, 372);
        RETURN_IF_ERROR(expect_O(Zero, "[2^372]phi(Q_A)"));
    }

    {
        // Verify that P + [2^372]Q = P
        digit_t OrderCoeff[MAXWORDS_ORDER];
        memset(OrderCoeff, 0, MAXWORDS_ORDER * 8);
        OrderCoeff[372 / RADIX] = 1LL << (372 % RADIX);

        point_proj_t AlsoP;
        ladder_3_pt(xP, xQ, xPQ, OrderCoeff, ALICE, AlsoP, A, CurveIsogeny);

        RETURN_IF_ERROR(expect_point_proj(phiP, AlsoP, "phi(P_A)", "phi(P_A) + [2^372]phi(Q_A)"));
    }

    return CRYPTO_SUCCESS;
}

CRYPTO_STATUS MakeEvil(kex_data B, kex_data EvilB, PCurveIsogenyStruct CurveIsogeny, unsigned int bits_known, digit_t *known_order, bool set_bit) {
    f2elm_t xP, xQ, xPQ;
    to_fp2mont(((f2elm_t*)B.pub)[0], xP);
    to_fp2mont(((f2elm_t*)B.pub)[1], xQ);
    to_fp2mont(((f2elm_t*)B.pub)[2], xPQ);

    // Get the Montgomery A parameter. xDBLe wants it in A/C form.
    f2elm_t A, C;
    get_A(xP, xQ, xPQ, A, CurveIsogeny);
    fpcopy751(CurveIsogeny->Montgomery_one, C[0]);
    fpzero751(C[1]);

    point_proj_t phiP;
    fp2copy751(xP, phiP->X);
    fp2zero751(phiP->Z);
    fpcopy751(CurveIsogeny->Montgomery_one, phiP->Z[0]);

    point_proj_t phiQ;
    fp2copy751(xQ, phiQ->X);
    fp2zero751(phiQ->Z);
    fpcopy751(CurveIsogeny->Montgomery_one, phiQ->Z[0]);

    point_proj_t phiD;
    fp2copy751(xPQ, phiD->X);
    fp2zero751(phiD->Z);
    fpcopy751(CurveIsogeny->Montgomery_one, phiD->Z[0]);

    // Generating the key (P+[n]Q, [m]Q, P+[n-m]Q).
    // Here m = 1+2^k, n = -(known_order_bits << k))
    unsigned int high_digit = 370 - bits_known;
    digit_t PCoeff1[MAXWORDS_ORDER];  // n
    digit_t PCoeff2[MAXWORDS_ORDER];  // m
    digit_t PCoeff3[MAXWORDS_ORDER];  // n-m
    digit_t Zero[MAXWORDS_ORDER];
    memset(PCoeff1, 0, MAXWORDS_ORDER * 8);
    memset(PCoeff2, 0, MAXWORDS_ORDER * 8);
    memset(PCoeff3, 0, MAXWORDS_ORDER * 8);
    memset(Zero, 0, MAXWORDS_ORDER * 8);

    PCoeff2[high_digit / 64] |= 1LL << (high_digit % 64);
    PCoeff2[0] |= 1;

    unsigned int i;
    mp_add(known_order, PCoeff1, PCoeff1, MAXWORDS_ORDER);
    if (set_bit) {
        PCoeff1[bits_known / 64] |= 1LL << (bits_known % 64);
    }
    for (i = 0; i < high_digit; ++i) {
        mp_shiftl1(PCoeff1, MAXWORDS_ORDER);
    }
    // These subtractions may underflow, which is fine, we think.
    mp_sub(Zero, PCoeff1, PCoeff1, MAXWORDS_ORDER);

    mp_sub(PCoeff1, PCoeff2, PCoeff3, MAXWORDS_ORDER);

    point_proj_t BadP, BadQ, BadD;
    // BadP = P+[n]Q
    ladder_3_pt(xP, xQ, xPQ, PCoeff1, ALICE, BadP, A, CurveIsogeny);
    // BadQ = [m]Q
    point_proj_t Scratch;
    ladder2(xQ, PCoeff2, BadQ, Scratch, A, 372, CurveIsogeny->owordbits, CurveIsogeny);
    // BadD = P+[n-m]Q
    ladder_3_pt(xP, xQ, xPQ, PCoeff3, ALICE, BadD, A, CurveIsogeny);

    f2elm_t BadxP, BadxQ, BadxPQ;
    norm_proj(BadP, BadxP);
    norm_proj(BadQ, BadxQ);
    norm_proj(BadD, BadxPQ);
    from_fp2mont(BadxP, ((f2elm_t*)EvilB.pub)[0]);
    from_fp2mont(BadxQ, ((f2elm_t*)EvilB.pub)[1]);
    from_fp2mont(BadxPQ, ((f2elm_t*)EvilB.pub)[2]);
    return CRYPTO_SUCCESS;
}

bool EqualShared(unsigned char *bob_shared, unsigned char *alice_shared) {
    unsigned int i;
    for (i = 0; i < NWORDS_FIELD; ++i) {
        if (((digit_t*)bob_shared)[i] != ((digit_t*)alice_shared)[i]) return false;
    }
    return true;
}

bool EqualPub(unsigned char *bob_pub, unsigned char *alice_pub) {
    unsigned int i;
    for (i = 0; i < 3 * 2 * NWORDS_FIELD; ++i) {
        if (((digit_t*)bob_pub)[i] != ((digit_t*)alice_pub)[i]) return false;
    }
    return true;
}

CRYPTO_STATUS PrintShared(unsigned char *bob_shared, unsigned char *alice_shared) {
    printf("SECRETS:\nbob   = ");
    blab_f2elm_t((felm_t*)bob_shared);
    printf("\nalice = ");
    blab_f2elm_t((felm_t*)alice_shared);
    printf("\n");

    return CRYPTO_SUCCESS;
}

CRYPTO_STATUS everything() {
    kex_data bob, alice, evil_bob;
    PCurveIsogenyStruct CurveIsogeny;
    RETURN_IF_ERROR(make_curve(&CurveIsogeny));
    RETURN_IF_ERROR(tests(CurveIsogeny));
    RETURN_IF_ERROR(alloc_kex_data(&bob, CurveIsogeny));
    RETURN_IF_ERROR(alloc_kex_data(&alice, CurveIsogeny));
    RETURN_IF_ERROR(alloc_kex_data(&evil_bob, CurveIsogeny));
    RETURN_IF_ERROR(KeyGeneration_B(bob.priv, bob.pub, CurveIsogeny));
    RETURN_IF_ERROR(KeyGeneration_A(alice.priv, alice.pub, CurveIsogeny, false));
    RETURN_IF_ERROR(SecretAgreement_B(bob.priv, alice.pub, bob.shared, true, CurveIsogeny));

    digit_t known_order[MAXWORDS_ORDER];
    memset(known_order, 0, sizeof(known_order));
    blab_order((digit_t*)alice.shared);
    unsigned int i;
    // Last two bits don't work
    for (i = 0; i < 370; ++i) {
        RETURN_IF_ERROR(MakeEvil(bob, evil_bob, CurveIsogeny, i, known_order, false));
        RETURN_IF_ERROR(SecretAgreement_A(alice.priv, evil_bob.pub, alice.shared, true, CurveIsogeny));
        bool bit_is_zero = EqualShared(bob.shared, alice.shared);
        RETURN_IF_ERROR(MakeEvil(bob, evil_bob, CurveIsogeny, i, known_order, true));
        RETURN_IF_ERROR(SecretAgreement_A(alice.priv, evil_bob.pub, alice.shared, true, CurveIsogeny));
        bool bit_is_one = EqualShared(bob.shared, alice.shared);

        if ((bit_is_one && bit_is_zero) || !(bit_is_one || bit_is_zero)) {
            printf("Oh noes! i = %d, is_zero = %d, is_one = %d\n", i, bit_is_zero, bit_is_one);
            return CRYPTO_ERROR;
        }
        if (bit_is_one) {
            known_order[i / 64] |= 1LL << (i % 64);
        }
        blab_order(known_order);
    }

    blab_order((digit_t*)alice.priv);
    return CRYPTO_SUCCESS;
}

int main() {
    CRYPTO_STATUS final = everything();
    if (final != CRYPTO_SUCCESS) {
        printf("error: %s\n", SIDH_get_error_message(final));
    }
    return 0;
}
