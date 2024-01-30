use std::{env::args, time::Duration};

use http_channel::PollingHttpChannel;
use parlay::{
    channel::MsgChannel,
    fpre::fpre_channel,
    garble_lang::compile,
    protocol::{mpc, Role},
};
use tokio::time::sleep;

mod http_channel;
mod server;

#[tokio::main]
async fn main() {
    if args().len() <= 1 {
        server::serve().await;
    } else if args().len() <= 4 {
        let mut args = args().into_iter();
        let _bin = args.next().unwrap();
        let url = args.next().unwrap();
        let session = args.next().unwrap();
        let participants = args.next().unwrap().parse::<usize>().unwrap();
        let mut fpre_channels = vec![];
        for p in 0..participants {
            let session = format!("{session}-fpre-{p}");
            let channel = PollingHttpChannel {
                url: url.clone(),
                session,
                client: reqwest::Client::new(),
                party_index: 0,
            };
            channel.join().await.unwrap();
            fpre_channels.push(MsgChannel(channel))
        }
        loop {
            let mut active_participants = 0;
            for channel in fpre_channels.iter_mut() {
                if channel.0.participants().await.unwrap() == 2 {
                    active_participants += 1;
                }
            }
            if active_participants == participants {
                break;
            } else {
                println!(
                    "Waiting for {} participants to join",
                    participants - active_participants
                );
                sleep(Duration::from_secs(1)).await;
            }
        }
        let other_party = 1;
        fpre_channel(other_party, &mut fpre_channels).await.unwrap()
    } else {
        let mut args = args().into_iter();
        let _bin = args.next().unwrap();
        let url = args.next().unwrap();
        let session = args.next().unwrap();
        let p_own = args.next().unwrap().parse::<usize>().unwrap();
        let input = args.next().unwrap().parse::<u32>().unwrap();
        let prg = compile("pub fn main(x: u32, y: u32, z: u32) -> u32 { x + y + z }").unwrap();
        let input = prg
            .parse_arg(p_own, &format!("{input}u32"))
            .unwrap()
            .as_bits();
        let p_eval = 0;
        let role = if p_own == p_eval {
            Role::PartyEval
        } else {
            Role::PartyContrib
        };
        let party_channel = PollingHttpChannel {
            url: url.clone(),
            session: session.clone(),
            client: reqwest::Client::new(),
            party_index: p_own,
        };
        party_channel.join().await.unwrap();
        let fpre_channel = PollingHttpChannel {
            url,
            session: format!("{session}-fpre-{p_own}"),
            client: reqwest::Client::new(),
            party_index: 1,
        };
        fpre_channel.join().await.unwrap();
        loop {
            let active_participants = party_channel.participants().await.unwrap();
            if active_participants < prg.circuit.input_gates.len() {
                println!(
                    "Waiting for {} other participants to join...",
                    prg.circuit.input_gates.len() - active_participants
                );
                sleep(Duration::from_secs(1)).await;
            } else {
                break;
            }
        }
        let parties = MsgChannel(party_channel);
        let fpre = MsgChannel(fpre_channel);
        let output = mpc(&prg.circuit, &input, fpre, parties, p_eval, p_own, role)
            .await
            .unwrap();
        if !output.is_empty() {
            let result = prg.parse_output(&output).unwrap();
            println!("{result}");
        }
    }
}
