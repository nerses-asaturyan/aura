| N      | Op                         | Param | Samples | Time            |
| ------ | -------------------------- | ----- | ------- | --------------- |
| 16     | full_pipeline              | —     | 10      | 14.57 ms ± 0.3% |
| 16     | serial_decrypt_per_tallier | —     | 10      | 1.832 ms ± 0.3% |
| 64     | full_pipeline              | —     | 10      | 50.96 ms ± 0.5% |
| 64     | serial_decrypt_per_tallier | —     | 10      | 7.373 ms ± 0.5% |
| 256    | full_pipeline              | —     | 10      | 200.3 ms ± 0.2% |
| 256    | serial_decrypt_per_tallier | —     | 10      | 29.36 ms ± 0.4% |
| 1,024  | full_pipeline              | —     | 10      | 888.0 ms ± 0.5% |
| 1,024  | serial_decrypt_per_tallier | —     | 10      | 118.2 ms ± 0.4% |
| 4,096  | full_pipeline              | —     | 10      | 4.334 s ± 0.3%  |
| 4,096  | serial_decrypt_per_tallier | —     | 10      | 474.4 ms ± 0.4% |
| 16,384 | full_pipeline              | —     | 10      | 31.78 s ± 0.2%  |
| 16,384 | serial_decrypt_per_tallier | —     | 10      | 2.004 s ± 0.3%  |
