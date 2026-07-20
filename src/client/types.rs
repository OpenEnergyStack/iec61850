// Function constraint data (FCD) or function constraint data attribute (FCDA)
pub struct DataReference {
    // Reference to a data point in the IEC 61850 model, e.g., "IED1/LLN0$ST$Val"
    pub reference: String,
    // Function constraint (e.g., "ST" for status, "MX" for measured value)
    pub fc: String,
}
// The protocol used for communication with the server. Currently, only MMS is supported.
pub enum Protocol {
    Mms,
    // Future: WebSocket, MQTT
}
