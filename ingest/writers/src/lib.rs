//! OCSF → graph projection. Entity IDs are a cross-language contract
//! (schemas/testvectors/entity_ids.json): the agents and API compute the same
//! IDs to address graph nodes.

use serde_json::{json, Value};
use sha2::{Digest, Sha256};

pub fn entity_id(kind: &str, tenant: &str, device: &str, natural: &str) -> String {
    let h = Sha256::digest(format!("{tenant}|{device}|{natural}").as_bytes());
    format!("{kind}_{}", &hex::encode(h)[..32])
}

pub fn proc_id(tenant: &str, device: &str, pid: u64, start_ms: u64) -> String {
    entity_id("proc", tenant, device, &format!("{pid}:{start_ms}"))
}

pub fn file_id(tenant: &str, device: &str, path: &str) -> String {
    entity_id("file", tenant, device, &path.to_lowercase())
}

/// Rows grouped per Cypher statement, so one batch = a handful of UNWIND queries.
#[derive(Default, Debug)]
pub struct GraphRows {
    pub procs: Vec<Value>,
    pub file_ops: Vec<Value>,
    pub dns: Vec<Value>,
    pub net: Vec<Value>,
}

fn u(v: &Value) -> u64 {
    v.as_u64().unwrap_or(0)
}

fn s(v: &Value) -> String {
    v.as_str().unwrap_or_default().to_string()
}

impl GraphRows {
    pub fn add(&mut self, tenant: &str, device: &str, ocsf: &Value) {
        let class = u(&ocsf["class_uid"]) as u32;
        let activity = u(&ocsf["activity_id"]);
        let time = u(&ocsf["time"]);
        let actor = &ocsf["actor"]["process"];
        let actor_id = || proc_id(tenant, device, u(&actor["pid"]), u(&actor["created_time"]));
        match (class, activity) {
            (1007, 1) => {
                let p = &ocsf["process"];
                let pp = &p["parent_process"];
                self.procs.push(json!({
                    "id": proc_id(tenant, device, u(&p["pid"]), u(&p["created_time"])),
                    "parent_id": (!pp.is_null()).then(|| proc_id(tenant, device, u(&pp["pid"]), u(&pp["created_time"]))),
                    "pid": u(&p["pid"]),
                    "start_ms": u(&p["created_time"]),
                    "image": s(&p["file"]["path"]),
                    "name": s(&p["file"]["name"]),
                    "image_id": file_id(tenant, device, &s(&p["file"]["path"])),
                    "cmdline": s(&p["cmd_line"]),
                    "user": s(&p["user"]["name"]),
                    "sha256": s(&p["file"]["hashes"][0]["value"]),
                    "time": time,
                }));
            }
            (1001, a) => {
                let rel = match a {
                    1 => "CREATED",
                    2 => "READ",
                    3 => "WROTE",
                    4 => "DELETED",
                    5 => "RENAMED",
                    _ => "MODIFIED",
                };
                let path = s(&ocsf["file"]["path"]);
                self.file_ops.push(json!({
                    "pid_id": actor_id(), "pid": u(&actor["pid"]), "start_ms": u(&actor["created_time"]),
                    "image": s(&actor["file"]["path"]),
                    "file_id": file_id(tenant, device, &path), "path": path, "name": s(&ocsf["file"]["name"]),
                    "rel": rel, "time": time,
                }));
            }
            (4003, _) => {
                let name = s(&ocsf["query"]["hostname"]).to_lowercase();
                let answers: Vec<Value> = ocsf["answers"]
                    .as_array()
                    .map(|a| {
                        a.iter()
                            .map(|x| s(&x["rdata"]))
                            .map(|ip| json!({ "ip": ip.clone(), "id": entity_id("sock", tenant, "", &format!("{ip}:*")) }))
                            .collect()
                    })
                    .unwrap_or_default();
                self.dns.push(json!({
                    "pid_id": actor_id(), "pid": u(&actor["pid"]), "start_ms": u(&actor["created_time"]),
                    "image": s(&actor["file"]["path"]),
                    "dns_id": entity_id("dns", tenant, "", &name), "name": name, "answers": answers, "time": time,
                }));
            }
            (4001, _) => {
                let ip = s(&ocsf["dst_endpoint"]["ip"]);
                let port = u(&ocsf["dst_endpoint"]["port"]);
                self.net.push(json!({
                    "pid_id": actor_id(), "pid": u(&actor["pid"]), "start_ms": u(&actor["created_time"]),
                    "image": s(&actor["file"]["path"]),
                    "sock_id": entity_id("sock", tenant, "", &format!("{ip}:{port}")),
                    "ip_id": entity_id("sock", tenant, "", &format!("{ip}:*")),
                    "ip": ip, "port": port,
                    "bytes_out": u(&ocsf["traffic"]["bytes_out"]), "bytes_in": u(&ocsf["traffic"]["bytes_in"]),
                    "time": time,
                }));
            }
            _ => {}
        }
    }

    pub fn is_empty(&self) -> bool {
        self.procs.is_empty() && self.file_ops.is_empty() && self.dns.is_empty() && self.net.is_empty()
    }

    /// Parameterized Cypher; telemetry is only ever passed as parameters.
    pub fn statements(&self, tenant: &str, device: &str) -> Vec<Value> {
        let host_id = entity_id("host", tenant, "", device);
        let mut out = vec![json!({
            "statement": "MERGE (h:Host {id: $host_id}) SET h.tenant_id = $tenant, h.device_id = $device",
            "parameters": { "host_id": host_id, "tenant": tenant, "device": device },
        })];
        // Actor processes may appear before (or without) their start event.
        const ACTOR: &str = "MERGE (p:Process {id: r.pid_id}) ON CREATE SET p.tenant_id = $tenant, p.device_id = $device, p.pid = r.pid, p.start_ms = r.start_ms, p.image = r.image";
        let mut push = |stmt: String, rows: &Vec<Value>| {
            if !rows.is_empty() {
                out.push(json!({ "statement": stmt, "parameters": { "rows": rows, "tenant": tenant, "device": device, "host_id": host_id } }));
            }
        };
        push(
            "UNWIND $rows AS r
             MERGE (p:Process {id: r.id})
             SET p.tenant_id = $tenant, p.device_id = $device, p.pid = r.pid, p.start_ms = r.start_ms,
                 p.image = r.image, p.name = r.name, p.cmdline = r.cmdline, p.user = r.user, p.sha256 = r.sha256
             WITH p, r
             MATCH (h:Host {id: $host_id}) MERGE (p)-[:ON]->(h)
             MERGE (img:File {id: r.image_id}) ON CREATE SET img.tenant_id = $tenant, img.device_id = $device, img.path = r.image, img.name = r.name
             MERGE (p)-[:IMAGE]->(img)
             WITH p, r WHERE r.parent_id IS NOT NULL
             MERGE (pp:Process {id: r.parent_id}) ON CREATE SET pp.tenant_id = $tenant, pp.device_id = $device
             MERGE (pp)-[:SPAWNED]->(p)"
                .into(),
            &self.procs,
        );
        push(
            format!(
                "UNWIND $rows AS r {ACTOR}
                 MERGE (f:File {{id: r.file_id}}) ON CREATE SET f.tenant_id = $tenant, f.device_id = $device, f.path = r.path, f.name = r.name
                 MERGE (p)-[e:FILE_OP {{op: r.rel}}]->(f)
                 ON CREATE SET e.first_ms = r.time, e.count = 0
                 SET e.last_ms = r.time, e.count = e.count + 1"
            ),
            &self.file_ops,
        );
        push(
            format!(
                "UNWIND $rows AS r {ACTOR}
                 MERGE (d:Domain {{id: r.dns_id}}) ON CREATE SET d.tenant_id = $tenant, d.name = r.name
                 MERGE (p)-[e:RESOLVED]->(d) ON CREATE SET e.first_ms = r.time, e.count = 0
                 SET e.last_ms = r.time, e.count = e.count + 1
                 WITH d, r UNWIND r.answers AS a
                 MERGE (ip:Endpoint {{id: a.id}}) ON CREATE SET ip.tenant_id = $tenant, ip.ip = a.ip
                 MERGE (d)-[:RESOLVES_TO]->(ip)"
            ),
            &self.dns,
        );
        push(
            format!(
                "UNWIND $rows AS r {ACTOR}
                 MERGE (ip:Endpoint {{id: r.ip_id}}) ON CREATE SET ip.tenant_id = $tenant, ip.ip = r.ip
                 MERGE (p)-[e:CONNECTED {{port: r.port}}]->(ip)
                 ON CREATE SET e.first_ms = r.time, e.count = 0, e.bytes_out = 0, e.bytes_in = 0, e.times = []
                 SET e.last_ms = r.time, e.count = e.count + 1,
                     e.bytes_out = e.bytes_out + r.bytes_out, e.bytes_in = e.bytes_in + r.bytes_in,
                     e.times = (e.times + r.time)[-32..]"
            ),
            &self.net,
        );
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entity_ids_match_shared_vectors() {
        let v: Value = serde_json::from_str(include_str!("../../../schemas/testvectors/entity_ids.json")).unwrap();
        for c in v["vectors"].as_array().unwrap() {
            assert_eq!(
                entity_id(c["kind"].as_str().unwrap(), c["tenant"].as_str().unwrap(), c["device"].as_str().unwrap(), c["natural"].as_str().unwrap()),
                c["id"].as_str().unwrap()
            );
        }
    }

    #[test]
    fn projects_process_and_network() {
        let mut g = GraphRows::default();
        g.add("t", "d", &json!({"class_uid":1007,"activity_id":1,"time":1,
            "process":{"pid":5,"created_time":9,"file":{"path":"C:\\a.exe","name":"a.exe"},
            "parent_process":{"pid":4,"created_time":2}}}));
        g.add("t", "d", &json!({"class_uid":4001,"activity_id":1,"time":2,
            "actor":{"process":{"pid":5,"created_time":9}},"dst_endpoint":{"ip":"203.0.113.1","port":443},
            "traffic":{"bytes_out":10,"bytes_in":2}}));
        assert_eq!(g.procs[0]["id"], proc_id("t", "d", 5, 9));
        assert_eq!(g.procs[0]["parent_id"], proc_id("t", "d", 4, 2));
        assert_eq!(g.net[0]["pid_id"], proc_id("t", "d", 5, 9));
        assert_eq!(g.statements("t", "d").len(), 3);
    }
}
