use accumulator::{Accumulator, Element, MembershipWitness, SecretKey};
use criterion::{criterion_group, criterion_main, Criterion};
use entities::issuer::Issuer;

//-------BENCHMARK PARAMETERS ------//
const NUM_SAMPLES: usize = 30; // the number of samples for each benchmark

criterion_group!(name = benches;
    config = Criterion::default().sample_size(NUM_SAMPLES);
    targets = issuer_gen, issuer_add, issuer_del
);
criterion_main!(benches);

/**
    Benchmark the Gen_I algorithm defined in Page 25.
*/
fn issuer_gen(c: &mut Criterion) {
    c.benchmark_group("issuer_core");

    println!("=================================================");
    println!("=Issuer Generation Benchmark");
    println!("=================================================");

    c.bench_function("Gen", |b| {
        b.iter(|| {
            // Creting a new issuer initializes all the public parameters
            Issuer::new(None);
        })
    });
}

/**
    Benchmark the Add_I algorithm defined in Page 25.
*/
fn issuer_add(c: &mut Criterion) {
    c.benchmark_group("issuer_core");
    println!("=================================================");
    println!("=Issuer Addition Benchmark");
    println!("=================================================");
    let acc = Accumulator::random(rand_core::OsRng {});
    let sk = SecretKey::new(None);
    let el = Element::random();
    c.bench_function("Add", |b| {
        b.iter(|| {
            // Create a memebership witness for the new holder, note that the accumulator value does not need to be updated.
            MembershipWitness::new(&el, acc, &sk);
        })
    });
}

/**
    Benchmark the Del_I algorithm defined in Page 25.
*/
fn issuer_del(c: &mut Criterion) {
    c.benchmark_group("issuer_core");
    println!("=================================================");
    println!("=Issuer Deletion Benchmark");
    println!("=================================================");

    let acc = Accumulator::random(rand_core::OsRng {});
    let sk = SecretKey::new(None);
    let el = Element::random();
    c.bench_function("Del", |b| {
        b.iter(|| {
            // Remove the revoked element from the accumulator
            let _ = acc.remove(&sk, el);
        })
    });
}
