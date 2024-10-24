// use criterion::{criterion_group, criterion_main, Criterion};

// fn my_function(n: u64) -> u64 {
//     (0..n).sum()
// }

// fn criterion_benchmark(c: &mut Criterion) {
//     c.bench_function("sum", |b| b.iter(|| my_function(1000)));
// }

// criterion_group!(benches, criterion_benchmark);
// criterion_main!(benches);