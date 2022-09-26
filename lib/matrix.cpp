#include "matrix.h"

using namespace osuCrypto;

mpz_class **initIntegerMatrix(int size)
{
    mpz_class **matrix = new mpz_class *[size];
    for (int i = 0; i < size; i++)
        matrix[i] = new mpz_class[size];
    return matrix;
}
mpq_class **initRationalMatrix(int size)
{
    mpq_class **matrix = new mpq_class *[size];
    for (int i = 0; i < size; i++)
        matrix[i] = new mpq_class[size];
    return matrix;
}

mpq_class **vandermondeMatrix(int m, int k)
{
    mpz_class **matrix = initIntegerMatrix(k);

    for (int i = 0; i < k; i++)
    {
        for (int j = 0; j < k; j++)
        {
            if (i < m)
            {
                if (i == j)
                    matrix[i][j] = 1;
                else
                    matrix[i][j] = 0;
            }
            else
            {
                mpz_ui_pow_ui(matrix[i][j].get_mpz_t(), i - m + 1, j);
            }
        }
    }
    mpq_class **new_matrix = initRationalMatrix(k);
    for (int i = 0; i < k; i++)
    {
        for (int j = 0; j < k; j++)
        {
            new_matrix[i][j] = matrix[i][j];
        }
    }
    return new_matrix;
}

mpq_class **inverseMatrix(mpq_class **matG, size_t nSize)
{
    mpq_class **matLU = initRationalMatrix(nSize);

    std::size_t i{0}, j{0}, k{0};

    // ******************** Step 1: row permutation (swap diagonal zeros) ********************
    std::vector<std::size_t> permuteLU; // Permute vector
    for (i = 0; i < nSize; ++i)
    {
        permuteLU.push_back(i); // Push back row index
    }

    for (j = 0; j < nSize; ++j)
    {
        double maxv{0.0};
        for (i = j; i < nSize; ++i)
        {
            const double currentv{std::abs(matG[permuteLU[i]][j].get_d())};
            if (currentv > maxv) // Swap rows
            {
                maxv = currentv;
                const std::size_t tmp{permuteLU[j]};
                permuteLU[j] = permuteLU[i];
                permuteLU[i] = tmp;
            }
        }
    }
    for (i = 0; i < nSize; ++i)
    {
        for (j = 0; j < nSize; j++)
            matLU[i][j] = matG[permuteLU[i]][j]; // Make a permuted matrix with new row order
    }

    // ******************** Step 2: LU decomposition (save both L & U in matLU) ********************
    for (i = 1; i < nSize; ++i)
    {
        for (j = i; j < nSize; ++j)
        {
            for (k = 0; k < i; ++k)
            {
                matLU[i][j] -= matLU[i][k] * matLU[k][j]; // Calculate U matrix
            }
        }
        for (k = i + 1; k < nSize; ++k)
        {
            for (j = 0; j < i; ++j)
            {
                matLU[k][i] -= matLU[k][j] * matLU[j][i]; // Calculate L matrix
            }
            matLU[k][i] /= matLU[i][i];
        }
    }

    // ******************** Step 3: L & U inversion (save both L^-1 & U^-1 in matLU_inv) ********************
    mpq_class **matLU_inv = initRationalMatrix(nSize);

    // matL inverse & matU inverse
    for (i = 0; i < nSize; ++i)
    {
        // L matrix inverse, omit diagonal ones
        matLU_inv[i][i] = 1.0;
        for (k = i + 1; k < nSize; ++k)
        {
            for (j = i; j <= k - 1; ++j)
            {
                matLU_inv[k][i] -= matLU[k][j] * matLU_inv[j][i];
            }
        }
        // U matrix inverse
        matLU_inv[i][i] = 1.0 / matLU[i][i];
        for (k = i; k > 0; --k)
        {
            for (j = k; j <= i; ++j)
            {
                matLU_inv[k - 1][i] -= matLU[k - 1][j] * matLU_inv[j][i];
            }
            matLU_inv[k - 1][i] /= matLU[k - 1][k - 1];
        }
    }

    // ******************** Step 4: Calculate G^-1 = U^-1 * L^-1 ********************
    // Lower part product
    for (i = 1; i < nSize; ++i)
    {
        for (j = 0; j < i; ++j)
        {
            const std::size_t jp{permuteLU[j]}; // Permute column back
            matLU[i][jp] = 0.0;
            for (k = i; k < nSize; ++k)
            {
                matLU[i][jp] += matLU_inv[i][k] * matLU_inv[k][j];
            }
        }
    }
    // Upper part product
    for (i = 0; i < nSize; ++i)
    {
        for (j = i; j < nSize; ++j)
        {
            const std::size_t jp{permuteLU[j]}; // Permute column back
            matLU[i][jp] = matLU_inv[i][j];
            for (k = j + 1; k < nSize; ++k)
            {
                matLU[i][jp] += matLU_inv[i][k] * matLU_inv[k][j];
            }
        }
    }
    return matLU; // Reused matLU as a result container
}
