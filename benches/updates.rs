use entities::issuer::Issuer;
use accumulator::{
    Accumulator, Deletion, Element, MembershipWitness, PublicKey, SecretKey
};
use bls12_381_plus::ff::Field;
use bls12_381_plus::Scalar;
use serde::{Serialize, Serializer};
use core::num;
use std::collections::{hash_map, HashMap, HashSet};
use std::vec::Vec;
use criterion::{
    criterion_group, criterion_main, Criterion,
};




//-------BENCHMARK PARAMETERS ------//

const USERS: usize =  100_001; // Total number of elements originally added
// Size of updates as (number of additions, number of deletions) for
// the original batch update protocols
const BATCH_UPDATE_CHANGES: [(usize, usize); 6] = [
        (0, 10),
        (10, 10),
        (0, 100),
        (100, 100),
        (0, 1000),
        (1000, 1000),
];
// Number of deletions for the single-server and threshold updates of ALLOSAUR
// Additions are not included, as both cases ignore additions
const UPDATES: [usize; 10] = [10_000, 20_000, 30_000, 40_000, 50_000, 60_000, 70_000, 80_000, 90_000, 100_000];
const CLIENT_UPDATES: [usize; 21] = [1, 500, 1000, 1500, 2000, 2500, 3000, 3500, 4000, 4500, 5000, 5500, 6000, 6500, 7000, 7500, 8000, 8500, 9000, 9500, 10000];
const BATCH_CLIENT_UPDATES: [usize; 21] = [1, 500, 1000, 1500, 2000, 2500, 3000, 3500, 4000, 4500, 5000, 5500, 6000, 6500, 7000, 7500, 8000, 8500, 9000, 9500, 10000];
const NUM_SAMPLES: usize = 30; // the number of samples for each benchmark



criterion_group!(name = benches;
    config = Criterion::default().sample_size(NUM_SAMPLES);
    targets = client_batch_update
);
criterion_main!(benches);


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
        let (non_revoked, revoked) = items.split_at(num_upds);
        witness.truncate(num_upds);

        
        

        // Benchmark of deletion method
        let mut coeff = Scalar::ONE;
    
        c.bench_function("Batch Deletion", |b| {
            b.iter(|| {
                coeff = key.batch_deletions(revoked).0;
                acc.0 *= coeff;
            })
        });
        
        // Benchmark of issuer update
        c.bench_function("Issuer", |b| {
            b.iter(|| {
                for wit in witness.iter_mut(){
                    wit.fast_update_assign(&coeff);
                }
            })
        });


        // Adds up the length of each message that must be sent
        // from each deletion update
        let (bytes_wit, bytes_acc) = (bincode::serialize(&witness[0]).expect("Serialization errror..."), bincode::serialize(&acc).expect("Serialization errror..."));
        let payload = bytes_wit.len() + bytes_acc.len();
        println!("Update server->user message size {} bytes", payload);
    }
}

// Benchmarks the single-server update of Section 3
fn client_update(c: &mut Criterion) {
    c.benchmark_group("client_update");


    for num_upds in CLIENT_UPDATES {
        println!("=================================================");
        println!(
            "=Client Benchmark with {} updates=",
            num_upds
        );
        println!("=================================================");

        // Creates a random array of users
        let key = SecretKey::new(None);
        let items: Vec<Element> = (0..USERS).map(|_| Element::random()).collect();
        let mut acc = Accumulator::random(rand_core::OsRng {});
        let mut witness: Vec<MembershipWitness> = (0..USERS).map(|i| MembershipWitness::new(&items[i], acc, &key)).collect();

        

        // Gets set of updates and deletions
        let (revoked, _non_revoked) = items.split_at(num_upds);
        
        //Update a witness for some user
        let pos = witness.len()-1;
        let y = items[pos].clone();
        let wit = witness[pos];
        
        let mut deletions: Vec<Deletion> = Vec::new();
        
        revoked.iter().for_each(|&d| {
            acc.remove_assign(&key, d);
            deletions.push(Deletion{0: acc, 1: d});
        });
        

        c.bench_function("Client_Deletion", |b| {
            b.iter(|| {
                wit.update(y, &deletions);
            })
        });

        // Adds up the length of each message that must be sent
        // from each deletion update
        let bytes_del = bincode::serialize(&deletions).expect("Serialization errror...");
        println!("Update server->user message size {} bytes",  bytes_del.len());
    }
}

 
// Batch update protocol of Vitto and Biryukov 2020 (https://eprint.iacr.org/2020/777)
fn client_batch_update(c: &mut Criterion) {
    c.benchmark_group("client_batch_update");
    let batch_client_updates: Vec<usize> = (0..20_000).step_by(200).collect();

    for num_ups in batch_client_updates {
        println!("=================================================");
        println!(
            "=Batch update Benchmark with {} deletions=",
            num_ups
        );
        println!("=================================================");

        // Creates an accumulator with the number of users
        let key = SecretKey::new(None);
        let items: Vec<Element> = (0..USERS).map(|_| Element::random()).collect();
        let mut acc = Accumulator::random(rand_core::OsRng {});

        // Takes the last user, gives them a witness
        let y = items.last().unwrap().clone();
        let mut witness = MembershipWitness::new(&y, acc, &key);

        // Creates lists of elements delete
        let (deletions, _) = items.split_at(num_ups);
        let deletions = deletions.to_vec();

        // Creates update polynomials
        let coefficients = acc.update_assign(&key, deletions.as_slice());

        // Benchmarks user response
        c.bench_function("Batch update user-side update", |b| {
            b.iter(|| {
                witness.batch_update(y, &deletions, &coefficients);
            })
        });

        witness.batch_update_assign(y, &deletions, &coefficients);
        assert!(witness.verify(y, PublicKey::from(&key), acc));
    }
}

/* 
// Multiparty threshold updates in ALLOSAUR
fn allosaur_update(c: &mut Criterion) {
    c.benchmark_group("allosaur_update");

    for num_dels in ALLOSAUR_CHANGES {
        println!("=================================================");
        println!("=ALLOSAUR Benchmark with {} deletions and threshold {} =", num_dels, THRESHOLD);
        println!("=================================================");

        // Creates secrets from shares, somewhat needlessly
       let alpha = SecretKey::new(None);
        let s =  SecretKey::new(None);
        let public_key_alpha = PublicKey(G2Projective::generator() * alpha.0);
        let public_key_s = PublicKey(G2Projective::generator() * s.0);

        let public_keys = PublicKeys {
            witness_key: public_key_alpha,
            sign_key: public_key_s,
        };

        let mut rng = rand_chacha::ChaChaRng::from_seed([1u8; 32]);

        let accumulator = Accumulator::random(&mut rng);
        let acc_params = AccParams::default();

        // Generates users with valid witnesses using the secret
        let users: Vec<User> = (0..USERS)
            .map(|_| {
                User::random(
                    &alpha,
                    &s,
                    acc_params,
                    accumulator,
                    public_keys,
                    1,
                    &mut rng,
                )
            })
            .collect();

        // Gets all the user witnesses to give to the servers
        let all_witnesses: HashMap<UserID, MembershipWitness> = users
            .iter()
            .map(|u| (u.get_id(), u.witness.as_ref().unwrap().witness))
            .collect();
        let all_users: HashSet<UserID> = users.iter().map(|u| u.id).collect();

        // Generates an array of servers
        // Here each server has the full accumulator secret key;
        // this is necessary for our fast and lazy delete to run the benchmark
        // but does not reflect how servers would actually handle secret keys
        let mut servers: Vec<Server> = (0..SHARES)
            .map(|_| Server {
                accumulators: vec![accumulator],
                wit_secret_key: alpha.clone(),
                public_keys,
                sign_secret_key: s.clone(),
                all_users: all_users.clone(),
                all_witnesses: all_witnesses.clone(),
                deletions: Vec::new(),
            })
            .collect();

        // Step 1 - remove a user from the accumulator which triggers an update
        servers.par_iter_mut().for_each(|s| {
            for u in &users[..num_dels] {
                let _ = s.quick_del(u.id).unwrap();
            }
        });

        // Benchmark the pre-update computations from the user
        let user = users[num_dels].clone();
        c.bench_function(
            "ALLOSAUR user-side pre-update",
            |b| {
                b.iter(|| {
                    user
                        .pre_update(servers[0].get_epoch(), SHARES, THRESHOLD)
                        .unwrap();
                })
            },
        );

        // Compute the actual pre-update data
        let (user_d, user_shares, user_values) = user
            .pre_update(servers[0].get_epoch(), SHARES, THRESHOLD)
            .unwrap();

        // Get the length of the data the user must send to each server
        let user_server_message = UserUpdateMessage {
            epoch: user_d,
            shares: user_shares[0].clone(),
        };
        // Print the length of data sent to *all* servers
        println!(
            "ALLOSAUR user 1 user->server message size {} bytes",
            serde_cbor::to_vec(&user_server_message).unwrap().len()*SHARES
        );

        // Benchmark the server side, for only one server
        c.bench_function(
            "ALLOSAUR server-side update ",
            |b| b.iter(|| servers[0].update(user_d, &user_shares[0])),
        );

        // Actually get the server responses, from all servers
        let dvs: Vec<(Vec<Scalar>, Vec<G1Projective>)> = (0..SHARES)
            .map(|i| servers[i].update(user_d, &user_shares[i]))
            .collect();

        // Get the length of data sent back to the user 
        let server_user_message = ServerUpdateMessage {
            d_poly: dvs[0].0.clone(),
            v_poly: dvs[0].1.clone(),
        };
         // Print the length of data sent from *all* servers
        println!(
            "ALLOSAUR user 1 server->user message size {} bytes",
            serde_cbor::to_vec(&server_user_message).unwrap().len()*SHARES
        );

        // Benchmark the user's computation on the resulting data
        c.bench_function("user-side post-update ", |b| {
            b.iter(|| {
                user
                    .post_update(
                        user.witness.as_ref().unwrap().witness,
                        THRESHOLD,
                        &user_shares,
                        &user_values,
                        &dvs,
                    )
                    .unwrap();
            })
        });

    }
}


// Various helper data structures to serialize update messages into byte strings

#[derive(Debug)]
struct UserUpdateMessage {
    epoch: usize,
    shares: Vec<Scalar>,
}

impl Serialize for UserUpdateMessage {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut output = Vec::with_capacity(64);
        output.append(&mut Uint::from(self.epoch).to_vec());
        output.append(&mut Uint::from(self.shares.len()).to_vec());
        for s in &self.shares {
            output.extend_from_slice(&s.to_bytes());
        }
        serializer.serialize_bytes(&output)
    }
}

#[derive(Debug)]
struct ServerUpdateMessage {
    d_poly: Vec<Scalar>,
    v_poly: Vec<G1Projective>,
}

impl Serialize for ServerUpdateMessage {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut output = Vec::with_capacity(64);
        output.append(&mut Uint::from(self.d_poly.len()).to_vec());
        for s in &self.d_poly {
            output.extend_from_slice(&s.to_bytes());
        }
        output.append(&mut Uint::from(self.v_poly.len()).to_vec());
        for s in &self.v_poly {
            output.extend_from_slice(&s.to_bytes().as_ref());
        }
        serializer.serialize_bytes(&output)
    }
}

#[derive(Debug)]
struct VBUpdateMessage {
    additions: Vec<Element>,
    deletions: Vec<Element>,
    deltas: Vec<Coefficient>,
}

impl Serialize for VBUpdateMessage {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut output = Vec::with_capacity(64);
        output.append(&mut Uint::from(self.additions.len()).to_vec());
        for s in &self.additions {
            output.extend_from_slice(&s.0.to_bytes());
        }
        output.append(&mut Uint::from(self.deletions.len()).to_vec());
        for s in &self.deletions {
            output.extend_from_slice(&s.0.to_bytes());
        }
        output.append(&mut Uint::from(self.deltas.len()).to_vec());
        for s in &self.deltas {
            output.extend_from_slice(&s.0.to_bytes().as_ref());
        }
        serializer.serialize_bytes(&output)
    }
}*/