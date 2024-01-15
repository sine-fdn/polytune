use multi_tandem::{
    channel::{Channel, Error},
    fpre::{f_pre, AuthBit, Delta},
};

#[test]
fn xor_homomorphic_mac() -> Result<(), Error> {
    let (a, b) = f_pre();

    // init:
    a.send("delta", &())?;
    b.send("delta", &())?;
    let delta_a: Delta = a.recv("delta")?;
    let delta_b: Delta = b.recv("delta")?;

    // random r1, r2, s1, s2:
    a.send("random shares", &(2 as u32))?;
    b.send("random shares", &(2 as u32))?;

    let r: Vec<AuthBit> = a.recv("random shares")?;
    let s: Vec<AuthBit> = b.recv("random shares")?;

    let (AuthBit(r1, mac_r1, key_s1), AuthBit(r2, mac_r2, key_s2)) = (r[0], r[1]);
    let (AuthBit(s1, mac_s1, key_r1), AuthBit(s2, mac_s2, key_r2)) = (s[0], s[1]);

    let (r3, mac_r3, key_s3) = {
        let r3 = r1 ^ r2;
        let mac_r3 = mac_r1 ^ mac_r2;
        let key_s3 = key_s1 ^ key_s2;
        (r3, mac_r3, key_s3)
    };
    let (s3, mac_s3, key_r3) = {
        let s3 = s1 ^ s2;
        let mac_s3 = mac_s1 ^ mac_s2;
        let key_r3 = key_r1 ^ key_r2;
        (s3, mac_s3, key_r3)
    };
    // verify that the MAC is XOR-homomorphic:
    assert_eq!(mac_r3, key_r3 ^ (r3 & delta_b));
    assert_eq!(mac_s3, key_s3 ^ (s3 & delta_a));
    Ok(())
}

#[test]
fn authenticated_and_shares() -> Result<(), Error> {
    for i in 0..2 {
        let (a, b) = f_pre();

        // init:
        a.send("delta", &())?;
        b.send("delta", &())?;
        let delta_a: Delta = a.recv("delta")?;
        let delta_b: Delta = b.recv("delta")?;

        // random r1, r2, s1, s2:
        a.send("random shares", &(2 as u32))?;
        b.send("random shares", &(2 as u32))?;

        let r: Vec<AuthBit> = a.recv("random shares")?;
        let s: Vec<AuthBit> = b.recv("random shares")?;

        let (auth_r1, auth_r2) = (r[0], r[1]);
        let (auth_s1, auth_s2) = (s[0], s[1]);

        let AuthBit(r1, mac_r1, key_s1) = auth_r1;
        let AuthBit(s1, _, key_r1) = auth_s1;
        let AuthBit(r2, _, _) = auth_r2;
        let AuthBit(s2, _, _) = auth_s2;

        if i == 0 {
            // uncorrupted authenticated (r1 XOR s1) AND (r2 XOR s2):
            a.send("AND shares", &vec![(auth_r1, auth_r2)])?;
            b.send("AND shares", &vec![(auth_s1, auth_s2)])?;
            let AuthBit(r3, mac_r3, key_s3) = a.recv::<Vec<AuthBit>>("AND shares")?[0];
            let AuthBit(s3, mac_s3, key_r3) = b.recv::<Vec<AuthBit>>("AND shares")?[0];
            assert_eq!(r3 ^ s3, (r1 ^ s1) & (r2 ^ s2));
            assert_eq!(mac_r3, key_r3 ^ (r3 & delta_b));
            assert_eq!(mac_s3, key_s3 ^ (s3 & delta_a));
        } else if i == 1 {
            // corrupted (r1 XOR s1) AND (r2 XOR s2):
            let auth_r1_corrupted = AuthBit(!r1, mac_r1, key_s1);
            a.send("AND shares", &vec![(auth_r1_corrupted, auth_r2)])?;
            b.send("AND shares", &vec![(auth_s1, auth_s2)])?;
            assert_eq!(a.recv::<String>("AND shares")?, "CheatingDetected");
            assert_eq!(b.recv::<String>("AND shares")?, "CheatingDetected");
        } else if i == 2 {
            // A would need knowledge of B's key and delta to corrupt the shared secret:
            let mac_r1_corrupted = key_r1 ^ (!r1 & delta_b);
            let auth_r1_corrupted = AuthBit(!r1, mac_r1_corrupted, key_s1);
            a.send("AND shares", &vec![(auth_r1_corrupted, auth_r2)])?;
            b.send("AND shares", &vec![(auth_s1, auth_s2)])?;
            assert_eq!(a.recv::<Vec<AuthBit>>("AND shares")?.len(), 1);
            assert_eq!(b.recv::<Vec<AuthBit>>("AND shares")?.len(), 1);
        }
    }
    Ok(())
}
