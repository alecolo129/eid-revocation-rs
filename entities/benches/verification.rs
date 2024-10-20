use accumulator::{Accumulator, Element, MembershipWitness, PublicKey, SecretKey};
use agora_allosaurus_rs as ago;
use criterion::{criterion_group, criterion_main, Criterion};
use entities::issuer::Issuer;
use entities::{Holder, Verifier};
use rand_core::RngCore;
use std::mem::size_of_val;
use std::vec::Vec;

//-------BENCHMARK PARAMETERS ------//
const NUM_SAMPLES: usize = 30; // the number of samples for each benchmark

criterion_group!(name = benches;
    config = Criterion::default().sample_size(NUM_SAMPLES);
    targets = wit_ver, zk_proofs
);
criterion_main!(benches);

/**
    Benchmarks for direct witness verification using the `VerifyWit_V` algorithm defined in page 25.
*/
fn wit_ver(c: &mut Criterion) {
    c.benchmark_group("client_core");
    println!("=================================================");
    println!("=Verify Witness Benchmark");
    println!("=================================================");

    let acc = Accumulator::random(rand_core::OsRng {});
    let sk = SecretKey::new(None);
    let pk = PublicKey::from(&sk);
    let el = Element::random();
    let wit = MembershipWitness::new(&el, acc, &sk);

    c.bench_function("WitVer", |b| {
        b.iter(|| {
            wit.verify(el, pk, acc);
        })
    });
}

/**
    Benchmarks for zk profs of membership `MemProof_H`, and proof verification `MemVer_V` as defined in page 31.
    As a comparison, we bench the proof contained in Anoncreds Agora open-source implementaion.
*/
fn zk_proofs(c: &mut Criterion) {
    c.benchmark_group("client_core");
    println!("=================================================");
    println!("=Verify Witness Benchmark");
    println!("=================================================");

    let mut iss = Issuer::new(None);
    let rh = iss.add("test").unwrap();

    let pp = iss.get_proof_params();
    let hol = Holder::new("test", rh, pp);
    let ver = Verifier::new(pp);

    let mut proof = None;
    c.bench_function("MemProof", |b| {
        b.iter(|| {
            // Benchmark proof generation
            proof = Some(hol.proof_membership(Some(pp)));
        })
    });

    c.bench_function("MemVer", |b| {
        b.iter(|| {
            // Benchmark proof verification
            ver.verify(proof.unwrap());
        })
    });

    // Compare to Agora proofs and verifications
    println!("=================================================");
    println!("=Agora Witness Verify Benchmark");
    println!("=================================================");

    let params = ago::AccParams::default();
    let mut server = ago::Server::new(&params);
    let mut users = Vec::new();
    for _ in 0..NUM_SAMPLES {
        users.push(ago::User::new(&server, ago::UserID::random()));
        server.add(users.last().unwrap().get_id());
        users.last_mut().unwrap().create_witness(&params, &server);
    }

    const SECURITY_BYTES: usize = 128 / 8;

    let mut proof = vec![None; 30];
    let mut ephemeral_challenge = [0u8; 2 * SECURITY_BYTES];
    let mut rand_gen = rand_core::OsRng;
    rand_gen.fill_bytes(&mut ephemeral_challenge);
    let mut i = 0;

    c.bench_function("AgoraMemProof", |b| {
        b.iter(|| {
            proof[i] = users[i].make_membership_proof(
                &params,
                &server.get_public_keys(),
                &ephemeral_challenge,
            );
            i += 1;
            i %= 10;
        })
    });

    let mut bit = true;
    c.bench_function("AgoraMemVer", |b| {
        b.iter(|| {
            bit &= ago::Witness::check_membership_proof(
                &proof[i].unwrap(),
                &params,
                &server.get_public_keys(),
                &server.get_accumulator(),
                &ephemeral_challenge,
            );
            i += 1;
            i %= 10;
        })
    });
    println!("{}", size_of_val(&proof[0].unwrap()));
    assert!(bit);
}

// Benchmarks for verification of holder proof
