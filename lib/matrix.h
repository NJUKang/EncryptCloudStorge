#pragma once
#include <cryptoTools/Common/BitVector.h>

#include <gmpxx.h>

using namespace osuCrypto;

mpz_class **initIntegerMatrix(int size);

mpq_class **initRationalMatrix(int size);

mpq_class **vandermondeMatrix(int m, int k);

mpq_class **inverseMatrix(mpq_class **matG, size_t nSize);
