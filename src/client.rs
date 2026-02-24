use crate::{mms::MmsTransport, types::IECData};

use async_trait::async_trait;
use mms::client::TLSConfig;
use std::time::Duration;

#[derive(Debug)]
pub enum Error {
    ConnectionFailed(String),
    DataAccessError(u8),
    ParseError(String),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::ConnectionFailed(msg) => write!(f, "Connection failed: {}", msg),
            Error::DataAccessError(code) => write!(f, "Data access error: {}", code),
            Error::ParseError(msg) => write!(f, "Parse error: {}", msg),
        }
    }
}

impl std::error::Error for Error {}

pub enum Protocol {
    Mms,
    // Future: WebSocket, MQTT
}

#[async_trait]
pub trait Transport: Send + Sync {
    async fn get_data_values(&self, refs: Vec<DataReference>) -> Result<Vec<IECData>, Error>;
    async fn get_server_directory(&self) -> Result<Vec<String>, Error>;
    async fn get_logical_device_directory(&self, ld_name: String) -> Result<Vec<String>, Error>;
}

// Function constraint data (FCD) or function constraint data attribute (FCDA)
pub struct DataReference {
    // Reference to a data point in the IEC 61850 model, e.g., "IED1/LLN0$ST$Val"
    pub reference: String,
    // Function constraint (e.g., "ST" for status, "MX" for measured value)
    pub fc: String,
}

pub struct ClientBuilder {
    protocol: Protocol,
    timeout: Duration,
    tls_config: Option<TLSConfig>,
}

impl ClientBuilder {
    pub fn new() -> Self {
        Self {
            protocol: Protocol::Mms, // Default
            timeout: Duration::from_secs(10),
            tls_config: None,
        }
    }

    /// Specify the protocol to use
    pub fn protocol(mut self, protocol: Protocol) -> Self {
        self.protocol = protocol;
        self
    }

    // Set timeout duration
    pub fn timeout(mut self, duration: Duration) -> Self {
        self.timeout = duration;
        self
    }

    /// Generic connect - just orchestrates, doesn't know MMS details
    pub async fn connect(self, host: &str, port: u16) -> Result<Client, Error> {
        let transport: Box<dyn Transport> = match self.protocol {
            Protocol::Mms => {
                // Delegate to the transport layer
                println!("timeout: {:?}", self.timeout);
                Box::new(MmsTransport::connect(host, port, self.timeout, self.tls_config).await?)
            } // Future: WebSocket, etc.
              // Protocol::WebSocket => {
              //     Box::new(WebSocketTransport::connect(host, port, self.timeout).await?)
              // }
        };

        Ok(Client { transport })
    }
}

pub struct Client {
    transport: Box<dyn Transport>,
}

impl Client {
    /// Read data values for the given references
    pub async fn get_data_values(&self, refs: Vec<DataReference>) -> Result<Vec<IECData>, Error> {
        self.transport.get_data_values(refs).await
    }
    pub async fn get_server_directory(&self) -> Result<Vec<String>, Error> {
        self.transport.get_server_directory().await
    }
    pub async fn get_logical_device_directory(
        &self,
        ld_name: String,
    ) -> Result<Vec<String>, Error> {
        self.transport.get_logical_device_directory(ld_name).await
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use super::*;

    #[derive(Default)]
    struct MockTransport {
        calls: Mutex<Vec<String>>,
    }

    #[async_trait]
    impl Transport for Arc<MockTransport> {
        async fn get_data_values(&self, refs: Vec<DataReference>) -> Result<Vec<IECData>, Error> {
            self.calls
                .lock()
                .unwrap()
                .push(format!("data:{}", refs.len()));
            Ok(vec![IECData::Boolean(true); refs.len()])
        }

        async fn get_server_directory(&self) -> Result<Vec<String>, Error> {
            self.calls.lock().unwrap().push("server_dir".to_string());
            Ok(vec!["IED1".to_string(), "IED2".to_string()])
        }

        async fn get_logical_device_directory(
            &self,
            ld_name: String,
        ) -> Result<Vec<String>, Error> {
            self.calls.lock().unwrap().push(format!("ld:{}", ld_name));
            Ok(vec!["IED1".to_string(), "IED2".to_string()])
        }
    }

    #[tokio::test]
    async fn client_forwards_references_to_transport() {
        let transport = Arc::new(MockTransport::default());
        let client = Client {
            transport: Box::new(transport.clone()),
        };

        let refs = vec![DataReference {
            reference: "IED1/LLN0.Mod.stVal".to_string(),
            fc: "ST".to_string(),
        }];

        let result = client
            .get_data_values(refs)
            .await
            .expect("client should return data");

        assert_eq!(result.len(), 1);
        let calls = transport.calls.lock().unwrap();
        assert_eq!(calls.as_slice(), &["data:1".to_string()]);
    }

    #[tokio::test]
    async fn client_forwards_server_directory_call() {
        let transport = Arc::new(MockTransport::default());
        let client = Client {
            transport: Box::new(transport.clone()),
        };

        let dirs = client
            .get_server_directory()
            .await
            .expect("client should return server directory");

        assert_eq!(dirs, vec!["IED1".to_string(), "IED2".to_string()]);
        let calls = transport.calls.lock().unwrap();
        assert_eq!(calls.as_slice(), &["server_dir".to_string()]);
    }

    #[tokio::test]
    async fn client_forwards_logical_device_directory_call() {
        let transport = Arc::new(MockTransport::default());
        let client = Client {
            transport: Box::new(transport.clone()),
        };

        let lds = client
            .get_logical_device_directory("LD0".to_string())
            .await
            .expect("client should return logical device directory");

        assert_eq!(lds, vec!["IED1".to_string(), "IED2".to_string()]);
        let calls = transport.calls.lock().unwrap();
        assert_eq!(calls.as_slice(), &["ld:LD0".to_string()]);
    }
}
