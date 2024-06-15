/*use accumulator::{holder, issuer, proof, verifier::{self, Verifier}};
use std::time::Instant;

const REPS: u32 = 10_000;


#[allow(dead_code)]
fn gen()->(issuer::Issuer, proof::ProofParamsPublic){
    //Issuer
    let iss = issuer::Issuer::new(Some(b"setup_acc"));
    let pp = iss.get_proof_params();
    return  (iss, pp);
}

#[allow(dead_code)]
fn test_issuance(iss: &mut issuer::Issuer, pp: &proof::ProofParamsPublic) -> (holder::Holder, f32){
    
    let time = Instant::now();
    let w = iss.add(b"test");
    let time = time.elapsed().as_secs_f32();
    assert!(w.is_some());
    let holder = holder::Holder::new(Some(*pp),w);
    return (holder, time);
}


#[allow(dead_code)]
fn test_produce_mem_proof(proof_params: &proof::ProofParamsPublic, hol: &holder::Holder)-> (proof::Proof, f32){
    
    let time = Instant::now();
    let proof = hol.proof_membership(&proof_params);
    let time = time.elapsed().as_secs_f32();
    assert!(proof.is_some());
    return (proof.unwrap(), time);
}

#[allow(dead_code)]
fn test_verify_mem_proof(ver: &verifier::Verifier, proof: proof::Proof)->f32{
    let time = Instant::now();
    let res = ver.verify(proof);
    let time = time.elapsed().as_secs_f32();
    assert!(res);
    return time;
}

fn main() {
    let mut iss= issuer::Issuer::new(None);
    let pp = iss.get_proof_params();
    let (hol, _) = test_issuance(&mut iss, &pp);
    
    let proof_params = iss.get_proof_params();
    let mut proof_data = vec![]; 
    let mut ver_data= vec![];

    let ver = Verifier::new(&proof_params);
    (0..REPS).for_each(|i| {
        println!("Loop {}", i+1);
        
        let (pr, time) = test_produce_mem_proof(&proof_params, &hol);
        proof_data.push(time);
        
        let time = test_verify_mem_proof(&ver, pr);
        ver_data.push(time)
    });

    println!("mean: {:?}", proof_data.iter().sum::<f32>() / proof_data.len() as f32);
    println!("mean {:?}", ver_data.iter().sum::<f32>() / ver_data.len() as f32);

    /*
    let file = File::create("issuance.txt");
    assert!(file.is_ok());
    let mut file = file.ok().unwrap();
    for time in data {
        assert!(writeln!(file, "{:?}", time).is_ok())
    }*/
}
*/

fn main(){
    
}