use entities::issuer::Issuer;
use accumulator::{
    Accumulator, Deletion, Element, MembershipWitness, PublicKey, SecretKey
};
use blsful::inner_types::{Field, Scalar};
use std::vec::Vec;
use criterion::{
    criterion_group, criterion_main, Criterion,
};




//-------BENCHMARK PARAMETERS ------//

const USERS: usize =  280_001; // Total number of elements originally added


const UPDATES: [usize; 10] = [10_000, 20_000, 30_000, 40_000, 50_000, 60_000, 70_000, 80_000, 90_000, 100_000];
//const CLIENT_UPDATES: [usize; 5] = [1, 10, 20, 30, 40];
const CLIENT_UPDATES: usize = 20_000;
const BATCH_CLIENT_UPDATES: [usize; 101] = [1, 200, 400, 600, 800, 1000, 1200, 1400, 1600, 1800, 2000, 2200, 2400, 2600, 2800, 3000, 3200, 3400, 3600, 3800, 4000, 4200, 4400, 4600, 4800, 5000, 5200, 5400, 5600, 5800, 6000, 6200, 6400, 6600, 6800, 7000, 7200, 7400, 7600, 7800, 8000, 8200, 8400, 8600, 8800, 9000, 9200, 9400, 9600, 9800, 10000, 10200, 10400, 10600, 10800, 11000, 11200, 11400, 11600, 11800, 12000, 12200, 12400, 12600, 12800, 13000, 13200, 13400, 13600, 13800, 14000, 14200, 14400, 14600, 14800, 15000, 15200, 15400, 15600, 15800, 16000, 16200, 16400, 16600, 16800, 17000, 17200, 17400, 17600, 17800, 18000, 18200, 18400, 18600, 18800, 19000, 19200, 19400, 19600, 19800, 20000];
const NUM_SAMPLES: usize = 30; // the number of samples for each benchmark



criterion_group!(name = benches;
    config = Criterion::default().sample_size(NUM_SAMPLES);
    //targets = issuer_gen, issuer_add, issuer_del
    //targets = client_upd_single
    targets = client_upd_sequential
);
criterion_main!(benches);



// Benchmarks the single-server update of Section 3
fn issuer_gen(c: &mut Criterion) {
    c.benchmark_group("issuer_core");
        
        println!("=================================================");
        println!(
            "=Issuer Generation Benchmark"
        );
        println!("=================================================");
    
        c.bench_function("Gen", |b| {
            b.iter(|| {
                Issuer::new(None);
            })
        });   
}

// Benchmarks the single-server update of Section 3
fn issuer_add(c: &mut Criterion) {
    c.benchmark_group("issuer_core");
        println!("=================================================");
        println!(
            "=Issuer Addition Benchmark"
        );
        println!("=================================================");
        let acc = Accumulator::random(rand_core::OsRng{});
        let sk = SecretKey::new(None);
        let el = Element::random();
        c.bench_function("Add", |b| {
            b.iter(|| {
                MembershipWitness::new(&el, acc, &sk);
            })
        });   
}

// Benchmarks the single-server update of Section 3
fn issuer_del(c: &mut Criterion) {
    c.benchmark_group("issuer_core");
        println!("=================================================");
        println!(
            "=Issuer Addition Benchmark"
        );
        println!("=================================================");
        let mut acc = Accumulator::random(rand_core::OsRng{});
        let sk = SecretKey::new(None);
        let el = Element::random();
        c.bench_function("Del", |b| {
            b.iter(|| {
                acc.remove_assign(&sk, el);
            })
        });   
}


// Benchmarks the single-server update of Section 3
fn client_upd_single(c: &mut Criterion) {
    c.benchmark_group("client_core");
        println!("=================================================");
        println!(
            "=Client Single Update Benchmark"
        );
        println!("=================================================");
        let acc = Accumulator::random(rand_core::OsRng{});
        let sk = SecretKey::new(None);
        let (el, deleted_el) = (Element::random(), Element::random());

        let mut wit = MembershipWitness::new(&el, acc, &sk);
        let new_acc = acc.remove(&sk, deleted_el);
    
        let del = Deletion(new_acc, deleted_el);
        c.bench_function("Upd", |b| {
            b.iter(|| {
                wit.update_assign(el, &[del])
            })
        });   
}


// Benchmarks the single-server update of Section 3
fn client_upd_sequential(c: &mut Criterion) {
    c.benchmark_group("client_core");
        println!("=================================================");
        println!(
            "=Client Sequential Update Benchmark"
        );
        println!("=================================================");
        
        //let mut upds: Vec<usize> = (0..=CLIENT_UPDATES).step_by(200).collect();
        let upds: Vec<usize> = (0..16).map(|i| 1<<i).step_by(2).collect();
        //upds[0] = 1;

        for upd in [5_000]{
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
            let mut witness = MembershipWitness::new(&y, acc, &sk);


            // Creates lists of elements delete
            let (deletions, _) = items.split_at(upd);
            let mut dels: Vec<Deletion> = Vec::new();
            let mut acc_t = acc.clone();

            let t = std::time::Instant::now();
            for &d in deletions{
                let new_acc = acc_t.remove_assign(&sk, d);
                dels.push(Deletion(new_acc, d));
            }
            println!("del: {:?}", t.elapsed());
            
            c.bench_function("SeqUpd", |b| {
                b.iter(|| {
                    let mut wit = witness.clone();
                    wit.update_assign(y, dels.as_slice());
                })
            });   
        }
}

// Benchmarks the single-server update of Section 3
fn wit_ver(c: &mut Criterion) {
    c.benchmark_group("client_core");
        println!("=================================================");
        println!(
            "=Verify Witness Benchmark"
        );
        println!("=================================================");

        let acc = Accumulator::random(rand_core::OsRng{});
        let sk = SecretKey::new(None);
        let pk = PublicKey::from(&sk);
        let el =  Element::random();
        let wit = MembershipWitness::new(&el, acc, &sk);
        
        c.bench_function("WitVer", |b| {
            b.iter(|| {
                wit.verify(el, pk, acc);
            })
        });   

        println!("{}", wit.verify(el, pk, acc));
}


// Benchmarks the single-server update of Section 3
fn issuer_update(c: &mut Criterion) {
    c.benchmark_group("issuer_update");


    for num_upds in UPDATES {
        println!("=================================================");
        println!(
            "=Issuer Update Benchmark with {} updates=",
            num_upds
        );
        println!("=================================================");

        // Creates a random array of users
        let key = SecretKey::new(None);
        let items: Vec<Element> = (0..USERS).map(|_| Element::random()).collect();
        let mut acc = Accumulator::random(rand_core::OsRng {});



        let mut witness: Vec<MembershipWitness> = (0..USERS).map(|i| MembershipWitness::new(&items[i], acc, &key)).collect();

        //Creats a witness for some user
        let y = items.last().unwrap().clone();

        // Gets set of updates and deletions
        let (_, revoked) = items.split_at(num_upds);
        witness.truncate(num_upds);


        // Benchmark of deletion method
        let mut coeff = Scalar::ONE;
    
        c.bench_function("Batch Deletion", |b| {
            b.iter(|| {
                coeff = key.batch_deletions(revoked).0;
                acc.0 *= coeff;
            })
        });
        
        


        // Adds up the length of each message that must be sent
        // from each deletion update
        let (bytes_wit, bytes_acc) = (bincode::serialize(&witness[0]).expect("Serialization errror..."), bincode::serialize(&acc).expect("Serialization errror..."));
        let payload = bytes_wit.len() + bytes_acc.len();
        println!("Update server->user message size {} bytes", payload);
    }
}


 
// Batch update protocol of Vitto and Biryukov 2020 (https://eprint.iacr.org/2020/777)
fn batch_update(c: &mut Criterion) {
    c.benchmark_group("client_batch_update");
    let mut batch_client_updates: Vec<usize> = (0..20_001).step_by(200).collect();
    batch_client_updates[0]=1;

   // let batch_client_updates: Vec<usize> = (0..16).map(|i| 1<<i).step_by(2).collect();

    for num_ups in [5000]{
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


// Batch update protocol of Vitto and Biryukov 2020 (https://eprint.iacr.org/2020/777)
fn batch_update_aggr(c: &mut Criterion) {
    c.benchmark_group("client_batch_update");
    //let batch_client_updates: Vec<usize> = (0..11_000).step_by(200).collect();

    let upd_size = 10_000;

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
        println!("Starting to generate up poly:");
        
        // Creates update polynomials
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
                witness.batch_updates(y, &deletions, coefficients.iter().map(|c| c.as_slice()).collect()).unwrap();
            })
        });
        assert!(witness.batch_updates_assign(y, &deletions, coefficients.iter().map(|c| c.as_slice()).collect()).unwrap().verify(y, PublicKey::from(&key), acc));
      
    }
}