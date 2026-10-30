//! Wire types shared by the sensor, the ingest gateway, and the writers.

pub mod v1 {
    tonic::include_proto!("scanu.v1");
}

pub use prost::Message;
