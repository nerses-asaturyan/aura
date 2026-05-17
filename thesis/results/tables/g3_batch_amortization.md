| Group               | Batch size | Individual | Batched  | Speedup |
| ------------------- | ---------- | ---------- | -------- | ------- |
| batch_verify_dleq   | 1          | 145.2 µs   | 80.54 µs | 1.80×   |
| batch_verify_dleq   | 10         | 1.442 ms   | 631.2 µs | 2.28×   |
| batch_verify_dleq   | 25         | 3.585 ms   | 1.550 ms | 2.31×   |
| batch_verify_dleq   | 50         | 7.188 ms   | 2.812 ms | 2.56×   |
| batch_verify_dleq   | 100        | 14.38 ms   | 5.249 ms | 2.74×   |
| batch_verify_encval | 1          | 178.8 µs   | 94.22 µs | 1.90×   |
| batch_verify_encval | 10         | 1.772 ms   | 757.3 µs | 2.34×   |
| batch_verify_encval | 25         | 4.446 ms   | 1.840 ms | 2.42×   |
| batch_verify_encval | 50         | 8.936 ms   | 3.268 ms | 2.73×   |
| batch_verify_encval | 100        | 17.92 ms   | 6.029 ms | 2.97×   |
| batch_verify_rep    | 1          | 80.83 µs   | 58.06 µs | 1.39×   |
| batch_verify_rep    | 10         | 797.2 µs   | 430.7 µs | 1.85×   |
| batch_verify_rep    | 25         | 2.027 ms   | 1.044 ms | 1.94×   |
| batch_verify_rep    | 50         | 4.041 ms   | 2.012 ms | 2.01×   |
| batch_verify_rep    | 100        | 8.166 ms   | 3.700 ms | 2.21×   |
