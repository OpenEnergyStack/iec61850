use crate::{
    client::{error::Error, mms::MmsTransport, types::DataReference, Protocol},
    types::{
        BufferedReportControlBlock, CancelObject, CancelResponse, ControlObject, ControlResponse,
        DataDefinition, IECData, Report, ReportType, SetBrcbValuesSettings, SetUrcbValuesSettings,
        UnbufferedReportControlBlock,
    },
};
use tokio::sync::mpsc;

use async_trait::async_trait;
use mms::client::TLSConfig;
use std::time::Duration;

#[async_trait]
pub(crate) trait Transport: Send + Sync {
    async fn get_data_values(&self, refs: Vec<DataReference>) -> Result<Vec<IECData>, Error>;
    async fn get_server_directory(&self) -> Result<Vec<String>, Error>;
    async fn get_logical_device_directory(&self, ld_name: String) -> Result<Vec<String>, Error>;
    async fn get_data_definition(&self, data_ref: DataReference) -> Result<DataDefinition, Error>;
    async fn get_data_set_directory(&self, data_set_ref: String) -> Result<Vec<String>, Error>;
    async fn set_brcb_values(
        &self,
        brcb_ref: String,
        settings: SetBrcbValuesSettings,
    ) -> Result<Vec<Result<(), Error>>, Error>;
    async fn set_urcb_values(
        &self,
        urcb_ref: String,
        settings: SetUrcbValuesSettings,
    ) -> Result<Vec<Result<(), Error>>, Error>;
    async fn get_brcb_values(&self, brcb_ref: String) -> Result<BufferedReportControlBlock, Error>;
    async fn get_urcb_values(
        &self,
        urcb_ref: String,
    ) -> Result<UnbufferedReportControlBlock, Error>;
    fn subscribe_reports(
        &self,
        control_block_ref: String,
        rpt_id: String,
        report_type: ReportType,
    ) -> mpsc::Receiver<Report>;
    async fn select(&self, ctrl_obj_ref: String) -> Result<(), Error>;
    async fn operate(&self, ctrl_obj: ControlObject) -> Result<ControlResponse, Error>;
    async fn select_with_value(&self, ctrl_obj: ControlObject) -> Result<ControlResponse, Error>;
    async fn cancel(&self, ctrl_obj: CancelObject) -> Result<CancelResponse, Error>;
    /// Subscribe to CommandTermination reports for a specific control object.
    /// Call this **before** issuing `operate()` so that a fast device cannot deliver
    /// the PDU before the subscription is registered.
    fn subscribe_command_termination(
        &self,
        ctrl_obj_ref: String,
    ) -> mpsc::Receiver<Result<ControlResponse, Error>>;
}

pub struct ClientBuilder {
    protocol: Protocol,
    timeout: Duration,
    tls_config: Option<TLSConfig>,
}

impl Default for ClientBuilder {
    fn default() -> Self {
        Self::new()
    }
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
    pub async fn get_data_definition(
        &self,
        data_ref: DataReference,
    ) -> Result<DataDefinition, Error> {
        self.transport.get_data_definition(data_ref).await
    }

    pub async fn get_data_set_directory(&self, data_set_ref: String) -> Result<Vec<String>, Error> {
        self.transport.get_data_set_directory(data_set_ref).await
    }

    pub async fn set_brcb_values(
        &self,
        brcb_ref: String,
        settings: SetBrcbValuesSettings,
    ) -> Result<Vec<Result<(), Error>>, Error> {
        self.transport.set_brcb_values(brcb_ref, settings).await
    }

    pub async fn set_urcb_values(
        &self,
        urcb_ref: String,
        settings: SetUrcbValuesSettings,
    ) -> Result<Vec<Result<(), Error>>, Error> {
        self.transport.set_urcb_values(urcb_ref, settings).await
    }

    pub async fn get_brcb_values(
        &self,
        brcb_ref: String,
    ) -> Result<BufferedReportControlBlock, Error> {
        self.transport.get_brcb_values(brcb_ref).await
    }

    pub async fn get_urcb_values(
        &self,
        urcb_ref: String,
    ) -> Result<UnbufferedReportControlBlock, Error> {
        self.transport.get_urcb_values(urcb_ref).await
    }

    pub fn subscribe_reports(
        &self,
        control_block_ref: String,
        rpt_id: String,
        report_type: ReportType,
    ) -> mpsc::Receiver<Report> {
        self.transport
            .subscribe_reports(control_block_ref, rpt_id, report_type)
    }

    pub async fn select(&self, ctrl_obj_ref: String) -> Result<(), Error> {
        self.transport.select(ctrl_obj_ref).await
    }

    pub async fn operate(&self, ctrl_obj: ControlObject) -> Result<ControlResponse, Error> {
        self.transport.operate(ctrl_obj).await
    }

    pub async fn select_with_value(
        &self,
        ctrl_obj: ControlObject,
    ) -> Result<ControlResponse, Error> {
        self.transport.select_with_value(ctrl_obj).await
    }

    pub async fn cancel(&self, ctrl_obj: CancelObject) -> Result<CancelResponse, Error> {
        self.transport.cancel(ctrl_obj).await
    }

    pub fn subscribe_command_termination(
        &self,
        ctrl_obj_ref: String,
    ) -> mpsc::Receiver<Result<ControlResponse, Error>> {
        self.transport.subscribe_command_termination(ctrl_obj_ref)
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

        async fn get_data_definition(
            &self,
            data_ref: DataReference,
        ) -> Result<DataDefinition, Error> {
            self.calls
                .lock()
                .unwrap()
                .push(format!("def:{}", data_ref.reference));
            todo!("Return proper DataDefinition")
        }

        async fn get_data_set_directory(&self, data_set_ref: String) -> Result<Vec<String>, Error> {
            self.calls
                .lock()
                .unwrap()
                .push(format!("ds:{}", data_set_ref));
            Ok(vec![])
        }

        async fn set_brcb_values(
            &self,
            brcb_ref: String,
            _settings: SetBrcbValuesSettings,
        ) -> Result<Vec<Result<(), Error>>, Error> {
            self.calls
                .lock()
                .unwrap()
                .push(format!("brcb:{}", brcb_ref));
            Ok(vec![])
        }

        async fn set_urcb_values(
            &self,
            urcb_ref: String,
            _settings: SetUrcbValuesSettings,
        ) -> Result<Vec<Result<(), Error>>, Error> {
            self.calls
                .lock()
                .unwrap()
                .push(format!("urcb:{}", urcb_ref));
            Ok(vec![])
        }

        async fn get_brcb_values(
            &self,
            brcb_ref: String,
        ) -> Result<BufferedReportControlBlock, Error> {
            self.calls
                .lock()
                .unwrap()
                .push(format!("get_brcb:{}", brcb_ref));
            todo!("Return proper BufferedReportControlBlock")
        }

        async fn get_urcb_values(
            &self,
            urcb_ref: String,
        ) -> Result<UnbufferedReportControlBlock, Error> {
            self.calls
                .lock()
                .unwrap()
                .push(format!("get_urcb:{}", urcb_ref));
            todo!("Return proper UnbufferedReportControlBlock")
        }

        fn subscribe_reports(
            &self,
            _control_block_ref: String,
            _rpt_id: String,
            _report_type: ReportType,
        ) -> mpsc::Receiver<Report> {
            let (_tx, rx) = mpsc::channel(1);
            rx
        }

        async fn select(&self, ctrl_obj_ref: String) -> Result<(), Error> {
            self.calls
                .lock()
                .unwrap()
                .push(format!("select:{}", ctrl_obj_ref));
            Ok(())
        }

        async fn operate(&self, ctrl_obj: ControlObject) -> Result<ControlResponse, Error> {
            self.calls
                .lock()
                .unwrap()
                .push(format!("operate:{}", ctrl_obj.ctrl_obj_ref));
            Ok(ControlResponse {
                ctrl_obj_ref: ctrl_obj.ctrl_obj_ref,
                ctl_val: ctrl_obj.ctl_val,
                oper_tm: ctrl_obj.oper_tm,
                origin: ctrl_obj.origin,
                ctl_num: ctrl_obj.ctl_num,
                t: ctrl_obj.t,
                test: ctrl_obj.test,
                check: ctrl_obj.check,
                add_cause: None,
            })
        }

        async fn select_with_value(
            &self,
            ctrl_obj: ControlObject,
        ) -> Result<ControlResponse, Error> {
            self.calls
                .lock()
                .unwrap()
                .push(format!("select_with_value:{}", ctrl_obj.ctrl_obj_ref));
            Ok(ControlResponse {
                ctrl_obj_ref: ctrl_obj.ctrl_obj_ref,
                ctl_val: ctrl_obj.ctl_val,
                oper_tm: ctrl_obj.oper_tm,
                origin: ctrl_obj.origin,
                ctl_num: ctrl_obj.ctl_num,
                t: ctrl_obj.t,
                test: ctrl_obj.test,
                check: ctrl_obj.check,
                add_cause: None,
            })
        }

        async fn cancel(&self, ctrl_obj: CancelObject) -> Result<CancelResponse, Error> {
            self.calls
                .lock()
                .unwrap()
                .push(format!("cancel:{}", ctrl_obj.ctrl_obj_ref));
            Ok(CancelResponse {
                ctrl_obj_ref: ctrl_obj.ctrl_obj_ref,
                ctl_val: ctrl_obj.ctl_val,
                oper_tm: ctrl_obj.oper_tm,
                origin: ctrl_obj.origin,
                ctl_num: ctrl_obj.ctl_num,
                t: ctrl_obj.t,
                test: ctrl_obj.test,
                add_cause: None,
            })
        }

        fn subscribe_command_termination(
            &self,
            _ctrl_obj_ref: String,
        ) -> mpsc::Receiver<Result<ControlResponse, Error>> {
            let (_tx, rx) = mpsc::channel(1);
            rx
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
