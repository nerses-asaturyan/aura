| Group                    | Batch size | Individual | Batched  | Speedup |
| ------------------------ | ---------- | ---------- | -------- | ------- |
| batch_verify_dleq        | 1          | 215.9 µs   | 119.7 µs | 1.80×   |
| batch_verify_dleq        | 10         | 2.018 ms   | 943.5 µs | 2.14×   |
| batch_verify_dleq        | 100        | 20.29 ms   | 6.587 ms | 3.08×   |
| batch_verify_dleq        | 25         | 5.239 ms   | 2.343 ms | 2.24×   |
| batch_verify_dleq        | 50         | 10.13 ms   | 4.234 ms | 2.39×   |
| batch_verify_encval      | 1          | 190.9 µs   | 97.82 µs | 1.95×   |
| batch_verify_encval      | 10         | 1.965 ms   | 928.2 µs | 2.12×   |
| batch_verify_encval      | 100        | 25.29 ms   | 8.879 ms | 2.85×   |
| batch_verify_encval      | 25         | 6.565 ms   | 2.747 ms | 2.39×   |
| batch_verify_encval      | 50         | 12.58 ms   | 4.936 ms | 2.55×   |
| batch_verify_rep         | 1          | 119.3 µs   | 84.45 µs | 1.41×   |
| batch_verify_rep         | 10         | 1.188 ms   | 628.9 µs | 1.89×   |
| batch_verify_rep         | 100        | 11.92 ms   | 5.580 ms | 2.14×   |
| batch_verify_rep         | 25         | 2.909 ms   | 1.601 ms | 1.82×   |
| batch_verify_rep         | 50         | 5.834 ms   | 2.918 ms | 2.00×   |
| N16/verify_batch         | 1          | —          | 2.483 ms | —       |
| N16/verify_batch         | 10         | —          | 25.32 ms | —       |
| N16/verify_batch_encval  | 1          | —          | 577.4 µs | —       |
| N16/verify_batch_encval  | 10         | —          | 4.866 ms | —       |
| N16/verify_batch_encval  | 1          | —          | 1.259 ms | —       |
| N16/verify_batch_encval  | 10         | —          | 13.08 ms | —       |
| N256/verify_batch        | 1          | —          | 5.988 ms | —       |
| N256/verify_batch        | 10         | —          | 59.20 ms | —       |
| N256/verify_batch        | 100        | —          | 633.1 ms | —       |
| N256/verify_batch        | 50         | —          | 310.1 ms | —       |
| N256/verify_batch_encval | 1          | —          | 568.8 µs | —       |
| N256/verify_batch_encval | 10         | —          | 5.235 ms | —       |
| N256/verify_batch_encval | 100        | —          | 45.07 ms | —       |
| N256/verify_batch_encval | 50         | —          | 22.54 ms | —       |
| N256/verify_batch_encval | 1          | —          | 1.271 ms | —       |
| N256/verify_batch_encval | 10         | —          | 13.00 ms | —       |
| N256/verify_batch_encval | 100        | —          | 130.4 ms | —       |
| N256/verify_batch_encval | 50         | —          | 64.77 ms | —       |
| N64/verify_batch         | 1          | —          | 2.975 ms | —       |
| N64/verify_batch         | 10         | —          | 32.32 ms | —       |
| N64/verify_batch         | 50         | —          | 162.3 ms | —       |
| N64/verify_batch_encval  | 1          | —          | 470.4 µs | —       |
| N64/verify_batch_encval  | 10         | —          | 4.840 ms | —       |
| N64/verify_batch_encval  | 50         | —          | 21.40 ms | —       |
| N64/verify_batch_encval  | 1          | —          | 959.1 µs | —       |
| N64/verify_batch_encval  | 10         | —          | 12.87 ms | —       |
| N64/verify_batch_encval  | 50         | —          | 66.57 ms | —       |
