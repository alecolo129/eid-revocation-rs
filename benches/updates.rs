use entities::issuer::Issuer;
use accumulator::{
    Accumulator, UpMsg, Element, MembershipWitness, PublicKey, SecretKey
};
use blsful::inner_types::Scalar;
use std::vec::Vec;
use criterion::{
    criterion_group, criterion_main, Criterion,
};




//-------BENCHMARK PARAMETERS ------//

const USERS: usize =  280_001; // Total number of elements originally added
const UPDATES: [usize; 10] = [10_000, 20_000, 30_000, 40_000, 50_000, 60_000, 70_000, 80_000, 90_000, 100_000];
const NUM_SAMPLES: usize = 30; // the number of samples for each benchmark



criterion_group!(name = benches;
    config = Criterion::default().sample_size(NUM_SAMPLES);
    targets = client_upd_single, client_upd_sequential, batch_update, batch_update_aggr
);
criterion_main!(benches);

/**
    Banchmark single update algorithm `WitUp_H` defined in page 25.
*/
fn client_upd_single(c: &mut Criterion) {
    c.benchmark_group("client_core");
        println!("=================================================");
        println!(
            "=Client Single Update Benchmark"
        );
        println!("=================================================");
        
        // Init parameters
        let acc = Accumulator::random(rand_core::OsRng{});
        let sk = SecretKey::new(None);
        
        // Create non-revoked and revoked elemnts
        let (el, deleted_el) = (Element::random(), Element::random());

        // Issue witness
        let wit = MembershipWitness::new(&el, acc, &sk);
        
        // Revoke element and get update message
        let new_acc = acc.remove(&sk, deleted_el);
        let del = UpMsg(new_acc, deleted_el);

        c.bench_function("Upd", |b| {
            b.iter(|| {
                // Update after single deletion
                let _ = wit.update(el, &[del]);
            })
        });   

}


/**
    Banchmark sequential application of single update algorithm `WitUp_H` defined in page 25.
*/
fn client_upd_sequential(c: &mut Criterion) {
    c.benchmark_group("client_core");
        println!("=================================================");
        println!(
            "=Client Sequential Update Benchmark"
        );
        println!("=================================================");
        
        let mut upds: Vec<usize> = (0..20_001).step_by(200).collect();
        upds[0]=1;

        for upd in upds{
            println!("=================================================");
            println!(
                "Running with {} deletions", upd
            );
            println!("=================================================");

            let acc = Accumulator::random(rand_core::OsRng{});
            let sk = SecretKey::new(None);
            let items: Vec<Element> = (0..USERS).map(|i| Element::hash(&format!("User {i}").into_bytes())).collect();

            // Takes the last user, gives them a witness
            let y = items.last().unwrap().clone();
            let witness = MembershipWitness::new(&y, acc, &sk);


            // Creates lists of elements delete
            let (deletions, _) = items.split_at(upd);
            let mut dels: Vec<UpMsg> = Vec::new();
            let mut acc_t = acc.clone();

            let t = std::time::Instant::now();
            for &d in deletions{
                let new_acc = acc_t.remove_assign(&sk, d);
                dels.push(UpMsg(new_acc, d));
            }
            println!("del: {:?}", t.elapsed());
            
            c.bench_function("SeqUpd", |b| {
                b.iter(|| {
                    // Sequentially update after multiple deletions
                    let mut wit = witness.clone();
                    wit.update_assign(y, dels.as_slice());
                })
            });   
        }
}


/**
    Banchmark batch update algorithm `WitUpBatch_H` defined in page 39 after a single batch deletion (i.e., without computing any aggregation).    
 */
fn batch_update(c: &mut Criterion) {
    c.benchmark_group("client_batch_update");
    
    let mut batch_client_updates: Vec<usize> = (0..20_001).step_by(200).collect();
    batch_client_updates[0]=1;

    for num_ups in batch_client_updates{
        println!("=================================================");
        println!(
            "=Batch update Benchmark with {} deletions=",
            num_ups
        );
        println!("=================================================");

        // Creates an accumulator with the number of users
        let key = SecretKey::new(None);
        let items: Vec<Element> = (0..USERS).map(|i| Element::hash(&format!("User {i}").into_bytes())).collect();
        let mut acc = Accumulator::random(rand_core::OsRng {});

        // Takes the last user, gives them a witness
        let y = items.last().unwrap().clone();
        let mut witness = MembershipWitness::new(&y, acc, &key);

        // Creates lists of elements delete
        let (deletions, _) = items.split_at(num_ups);
        let deletions = deletions.to_vec();

        // Creates update polynomials
        /*c.bench_function("Issuer Update Poly Gen", |b| {
            b.iter(|| {
                acc.update(&key, deletions.as_slice())
            })
        });*/
        let coefficients = acc.update_assign(&key, deletions.as_slice());

        // Benchmarks user response
        c.bench_function("Batch update user-side update", |b| {
            b.iter(|| {
                witness.batch_update(y, &deletions, &coefficients).unwrap();
            })
        });

        witness.batch_update_assign(y, &deletions, &coefficients).unwrap();
        assert!(witness.verify(y, PublicKey::from(&key), acc));
    }
}


/**
    Banchmark aggregation batch update algorithm `WitUpBatch_H` aggregating multiple updates using the `WitUpBatch_H` algorithm defined in page 39.
    As a comparison, we also banchmark a sequential application of the batch update algorithm without using any aggregation.    
 */
fn batch_update_aggr(c: &mut Criterion) {
    c.benchmark_group("client_batch_update");

    let upd_size = 5_000;

    let mut ms: Vec<usize> = (1..200).step_by(10).collect();
    ms.append(&mut (200..=upd_size).step_by(200).collect());

    // Creates an accumulator with the number of users
    let key = SecretKey::new(None);
    let items: Vec<Element> = (0..upd_size).map(|i| Element::hash(&format!("User {i}").into_bytes())).collect();
    let mut acc = Accumulator::random(rand_core::OsRng {});

    for m in ms{
        println!("=======================================================================================");
        println!(
            "=Batch Update with vs without aggregation with {} deletions, and batches of size {}=",
            upd_size, m
        );
        println!("=======================================================================================");
        
        // Take the first user, gives him a witness
        let y = items[0];
        let mut witness = MembershipWitness::new(&y, acc, &key);

        // Creates lists of elements delete
        let deletions: Vec<&[Element]> = items[1..].chunks(m).collect();
        
        // Creates update polynomials
        println!("Starting to generate up poly:");
        let coefficients: Vec<Vec<accumulator::Coefficient>> = deletions.iter().map(|del|  acc.update_assign(&key, &del)).collect();
        println!("Upd poly finished");
        
        // Batch update no aggregation
        c.bench_function("Batch update", |b| {
            b.iter(|| {
                coefficients.iter().zip(&deletions).for_each(|(c,del)| {witness.batch_update(y, del, c).unwrap();});
            })
        });
        
        // Batch update aggregation
        c.bench_function("Batch update with aggregation", |b| {
            b.iter(|| {
                witness.batch_update_aggr(y, &deletions, coefficients.iter().map(|c| c.as_slice()).collect()).unwrap();
            })
        });
        assert!(witness.batch_update_aggr_assign(y, &deletions, coefficients.iter().map(|c| c.as_slice()).collect()).unwrap().verify(y, PublicKey::from(&key), acc)); 
    }
}