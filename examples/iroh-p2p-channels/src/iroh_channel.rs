use polytune::channel::Channel;
use quinn::Connection;
use tracing::info;

pub(crate) struct IrohChannel {
    pub(crate) conns: Vec<Option<Connection>>,
    pub(crate) max_msg_bytes: usize,
}

impl IrohChannel {
    pub(crate) fn new(conns: Vec<Option<Connection>>, max_msg_bytes: usize) -> Self {
        Self {
            conns,
            max_msg_bytes,
        }
    }
}

impl Channel for IrohChannel {
    type SendError = anyhow::Error;
    type RecvError = anyhow::Error;

    async fn send_bytes_to(
        &mut self,
        p: usize,
        _phase: &str,
        _i: usize,
        _remaining: usize,
        msg: Vec<u8>,
    ) -> Result<(), Self::SendError> {
        info!("sending {} bytes to {p}", msg.len());
        let mut send = self.conns[p].as_ref().unwrap().open_uni().await?;
        send.write_all(&msg).await?;
        send.finish().await?;
        Ok(())
    }

    async fn recv_bytes_from(
        &mut self,
        p: usize,
        _phase: &str,
        _i: usize,
    ) -> Result<Vec<u8>, Self::RecvError> {
        let mut recv = self.conns[p].as_ref().unwrap().accept_uni().await?;
        let msg = recv.read_to_end(self.max_msg_bytes).await?;
        info!("received {} bytes from {p}", msg.len());
        Ok(msg)
    }
}
