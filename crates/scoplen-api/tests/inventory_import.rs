// SPDX-License-Identifier: Apache-2.0
use scoplen_api::{
    account_browser::{
        AccountBrowserAccessOperation as Browser, AccountBrowserAccessRequirement,
        AccountBrowserAccessScope,
    },
    auth::{DeviceAccessOperation as Device, DeviceAccessScope},
    inventory::InventoryType,
    inventory_import::{
        InventoryCsvErrorKind as Kind, InventoryImportFields, InventoryImportPair,
        InventoryImportRequest, InventoryImportResult, InventoryImportRow, MAX_INVENTORY_CSV_BYTES,
        MAX_INVENTORY_IMPORT_REQUEST_BYTES, MAX_INVENTORY_IMPORT_RESULT_BYTES,
        inventory_csv_preview, parse_inventory_csv,
    },
    organization::OrganizationCodecError,
};
use serde_json::{Value, json};
use uuid::Uuid;

const HEADER: &str = "name,address,port,username,login_name";
fn id(value: u64) -> Uuid {
    format!("019bdad6-b800-7000-8000-{value:012}").parse().unwrap()
}
fn row(number: u64) -> InventoryImportRow {
    InventoryImportRow {
        host_id: id(number),
        access_profile_id: id(number + 1),
        fields: InventoryImportFields {
            name: "Example".into(),
            address: "example.test".into(),
            port: 22,
            username: "operator".into(),
            login_name: Some("Operations".into()),
        },
    }
}
fn request() -> InventoryImportRequest {
    InventoryImportRequest { rows: vec![row(10), row(20)] }
}
fn result(request: &InventoryImportRequest) -> InventoryImportResult {
    InventoryImportResult {
        items: request
            .rows
            .iter()
            .map(|row| InventoryImportPair {
                host_id: row.host_id,
                access_profile_id: row.access_profile_id,
            })
            .collect(),
    }
}

#[test]
fn shared_csv_quotes_records_bom_defaults_and_exact_whitespace() {
    for ending in ["\n", "\r\n"] {
        let csv = format!(
            "\u{feff}{HEADER}{ending}\" A,\"\"B\"\" \", example.test ,, operator ,{ending}"
        );
        let rows = parse_inventory_csv(csv.as_bytes()).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].name, " A,\"B\" ");
        assert_eq!(rows[0].address, " example.test ");
        assert_eq!(rows[0].username, " operator ");
        assert_eq!(rows[0].port, 22);
        assert_eq!(rows[0].login_name, None);
        let preview: Value =
            serde_json::from_str(&inventory_csv_preview(csv.as_bytes()).unwrap()).unwrap();
        assert_eq!(preview["rows"][0]["name"], rows[0].name);
        assert!(preview["rows"][0].get("host_id").is_none());
    }
    let csv = format!("{HEADER}\n\"line\none\",host.test,65535,user,\"line\r\ntwo\"");
    let rows = parse_inventory_csv(csv.as_bytes()).unwrap();
    assert_eq!(rows[0].name, "line\none");
    assert_eq!(rows[0].login_name.as_deref(), Some("line\r\ntwo"));
}

#[test]
fn csv_rejections_are_fixed_source_free_data_record_diagnostics() {
    assert_eq!(parse_inventory_csv(&[0xff]).unwrap_err().kind, Kind::InvalidUtf8);
    for text in ["", "\u{feff}", HEADER] {
        assert_eq!(parse_inventory_csv(text.as_bytes()).unwrap_err().kind, Kind::EmptyInput);
    }
    for header in [
        "name,address,port,username,username",
        "address,name,port,username,login_name",
        "name,address,port,username,login_name,extra",
        "\u{feff}\u{feff}name,address,port,username,login_name",
    ] {
        assert_eq!(
            parse_inventory_csv(format!("{header}\nx,h,22,u,").as_bytes()).unwrap_err().kind,
            Kind::InvalidHeader
        );
    }
    for suffix in [
        "\n",
        "x,h,22,u",
        "x,h,22,u,,extra",
        "x\"q,h,22,u,",
        "\"x\"oops,h,22,u,",
        "\"unclosed,h,22,u,",
        "x,h,22,u,\rnext",
    ] {
        let error = parse_inventory_csv(format!("{HEADER}\n{suffix}").as_bytes()).unwrap_err();
        assert_eq!(error.kind, Kind::InvalidCsv, "{suffix:?}");
        assert_eq!(error.record, Some(1));
    }
    for (suffix, field) in [
        ("private,h,01,u,", "port"),
        ("private,h,0,u,", "port"),
        ("private,h,+22,u,", "port"),
        ("private,h,65536,u,", "port"),
        ("private,h,22.0,u,", "port"),
        ("private,h,2e1,u,", "port"),
        ("private,h, 22,u,", "port"),
        ("private,,22,u,", "address"),
        ("private,h,22,,", "username"),
        (",h,22,u,", "name"),
        ("e\u{301},h,22,u,", "name"),
    ] {
        let error = parse_inventory_csv(format!("{HEADER}\n{suffix}").as_bytes()).unwrap_err();
        assert_eq!(error.kind, Kind::InvalidCell);
        assert_eq!(error.record, Some(1));
        assert_eq!(error.field, Some(field));
        assert!(!format!("{error:?} {error} {}", error.to_json()).contains("private"));
    }
    let error = parse_inventory_csv(
        format!("{HEADER}\n\"one\nphysical\nrecord\",h,22,u,\n,h,22,u,").as_bytes(),
    )
    .unwrap_err();
    assert_eq!(error.record, Some(2));
}

#[test]
fn typed_rows_convert_only_the_reciprocal_direct_host_login_fields() {
    let request = request();
    let encoded = request.to_json().unwrap();
    assert_eq!(InventoryImportRequest::from_json(&encoded).unwrap(), request);
    assert!(!format!("{request:?}").contains("example.test"));
    for row in &request.rows {
        let (host, login) = row.inventory_creates().unwrap();
        assert_eq!(host.fields.kind(), InventoryType::Host);
        assert_eq!(login.fields.kind(), InventoryType::AccessProfile);
        let host: Value = serde_json::from_slice(&host.fields.to_json().unwrap()).unwrap();
        let login: Value = serde_json::from_slice(&login.fields.to_json().unwrap()).unwrap();
        assert_eq!(
            host,
            json!({"name":"Example","address":"example.test","port":22,"default_profile":row.access_profile_id.to_string()})
        );
        assert_eq!(
            login,
            json!({"host":row.host_id.to_string(),"username":"operator","route":0,"name":"Operations"})
        );
    }
    let mut absent = row(30);
    absent.fields.login_name = None;
    let (_, login) = absent.inventory_creates().unwrap();
    assert!(!String::from_utf8(login.fields.to_json().unwrap()).unwrap().contains("\"name\""));
}

#[test]
fn direct_json_rejects_unknown_null_duplicates_id_aliases_and_port_aliases() {
    let request = request();
    let encoded = String::from_utf8(request.to_json().unwrap()).unwrap();
    for replacement in ["22.0", "22e0", "\"22\"", "null", "0", "65536", "-1", "true"] {
        assert!(
            InventoryImportRequest::from_json(
                encoded.replace("\"port\":22", &format!("\"port\":{replacement}")).as_bytes()
            )
            .is_err()
        );
    }
    for value in [json!(null), json!(""), json!("e\u{301}")] {
        for name in ["name", "address", "username", "login_name"] {
            let mut body: Value = serde_json::from_str(&encoded).unwrap();
            body["rows"][0][name] = value.clone();
            assert!(
                InventoryImportRequest::from_json(&serde_json::to_vec(&body).unwrap()).is_err()
            );
        }
    }
    for invalid in [
        encoded.replacen("\"rows\":", "\"extra\":1,\"rows\":", 1),
        encoded.replacen("\"name\":", "\"credential\":\"x\",\"name\":", 1),
        encoded.replacen("\"port\":22", "\"port\":22,\"port\":22", 1),
        encoded.replace(&id(10).to_string(), &id(10).to_string().to_uppercase()),
        encoded.replace(&id(11).to_string(), &id(10).to_string()),
        encoded.replace(&id(20).to_string(), &id(11).to_string()),
        "{\"rows\":[]}".into(),
        "{\"rows\":null}".into(),
    ] {
        assert!(
            InventoryImportRequest::from_json(invalid.as_bytes()).is_err(),
            "invalid input accepted"
        );
    }
}

#[test]
fn complete_bounds_include_original_whitespace_and_response_extensions() {
    let csv = format!("{HEADER}\nx,h,22,u,{}", "x".repeat(16384));
    assert!(parse_inventory_csv(csv.as_bytes()).is_ok());
    assert!(parse_inventory_csv(format!("{csv}x").as_bytes()).is_err());
    let line = "x,h,22,u,\n";
    let hundred = format!("{HEADER}\n{}", line.repeat(100));
    assert_eq!(parse_inventory_csv(hundred.as_bytes()).unwrap().len(), 100);
    assert_eq!(
        parse_inventory_csv(format!("{hundred}{line}").as_bytes()).unwrap_err().kind,
        Kind::TooManyRecords
    );
    assert_eq!(
        parse_inventory_csv(&vec![b'x'; MAX_INVENTORY_CSV_BYTES + 1]).unwrap_err().kind,
        Kind::TooLarge
    );
    assert_ne!(
        parse_inventory_csv(&vec![b'x'; MAX_INVENTORY_CSV_BYTES]).unwrap_err().kind,
        Kind::TooLarge
    );
    let encoded = request().to_json().unwrap();
    let pad = |bytes: &[u8], size: usize| {
        let mut result = vec![b' '; size - bytes.len()];
        result.extend_from_slice(bytes);
        result
    };
    assert!(
        InventoryImportRequest::from_json(&pad(&encoded, MAX_INVENTORY_IMPORT_REQUEST_BYTES))
            .is_ok()
    );
    assert_eq!(
        InventoryImportRequest::from_json(&pad(&encoded, MAX_INVENTORY_IMPORT_REQUEST_BYTES + 1)),
        Err(OrganizationCodecError::TooLarge)
    );
    let response = result(&request()).to_json().unwrap();
    assert!(
        InventoryImportResult::from_json(&pad(&response, MAX_INVENTORY_IMPORT_RESULT_BYTES))
            .is_ok()
    );
    assert_eq!(
        InventoryImportResult::from_json(&pad(&response, MAX_INVENTORY_IMPORT_RESULT_BYTES + 1)),
        Err(OrganizationCodecError::TooLarge)
    );
    let request =
        InventoryImportRequest { rows: (0..100).map(|index| row(100 + index * 2)).collect() };
    assert!(request.to_json().is_ok());
    assert!(result(&request).to_json().is_ok());
    let mut overflow = request;
    overflow.rows.push(row(999));
    assert!(overflow.to_json().is_err());
}

#[test]
fn ordered_result_is_request_bound_and_metadata_checked() {
    let request = request();
    let result = result(&request);
    let bytes = result.to_json().unwrap();
    assert_eq!(
        InventoryImportResult::from_http_json(&bytes, Some("no-store"), Some("no-cache"), &request)
            .unwrap(),
        result
    );
    assert!(
        InventoryImportResult::from_http_json(&bytes, None, Some("no-cache"), &request).is_err()
    );
    let mut changed = result.clone();
    changed.items.reverse();
    assert!(changed.validate_for_request(&request).is_err());
    changed.items.pop();
    assert!(changed.validate_for_request(&request).is_err());
    changed = result.clone();
    changed.items[0].host_id = id(99);
    assert!(changed.validate_for_request(&request).is_err());
    let mut response: Value = serde_json::from_slice(&bytes).unwrap();
    response["extension"] = json!({"ok":true});
    response["items"][0]["extension"] = Value::Null;
    assert!(
        InventoryImportResult::from_json(&serde_json::to_vec(&response).unwrap())
            .unwrap()
            .validate_for_request(&request)
            .is_ok()
    );
}

#[test]
fn exact_import_post_mapping_adds_no_job_crud_or_new_scope() {
    let route = "/api/v1/orgs/{org}/inventory/imports";
    assert_eq!(Device::from_route("POST", route), Some(Device::InventoryImportCreate));
    assert_eq!(
        Device::InventoryImportCreate.accepted_scopes(),
        &[DeviceAccessScope::InventoryWrite]
    );
    assert_eq!(Browser::from_route("POST", route), Some(Browser::InventoryImportCreate));
    assert_eq!(
        Browser::InventoryImportCreate.requirement(),
        AccountBrowserAccessRequirement::AnyScope(&[AccountBrowserAccessScope::InventoryWrite])
    );
    assert!(Browser::InventoryImportCreate.uses_browser_writer_receipt());
    for method in ["GET", "PUT", "PATCH", "DELETE"] {
        assert_eq!(Device::from_route(method, route), None);
        assert_eq!(Browser::from_route(method, route), None);
    }
    assert_eq!(Device::from_route("POST", "/api/v1/orgs/{org}/inventory/imports/{id}"), None);
}

#[test]
fn independent_csv_wire_binding_and_complete_boundary_vectors_use_public_exports() {
    let document = scoplen_test_vectors::VectorDocument::parse_str(include_str!(
        "../../../vectors/organization-inventory-import.json"
    ))
    .unwrap();
    for vector in document.vectors {
        match vector.kind.as_str() {
            "inventory.import.csv" => {
                let input = vector
                    .input
                    .as_bytes()
                    .as_chunks::<2>()
                    .0
                    .iter()
                    .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
                    .collect::<Vec<_>>();
                let actual = inventory_csv_preview(&input).unwrap_or_else(|error| error.to_json());
                assert_eq!(actual, vector.expected, "{}", vector.id);
            }
            "inventory.import.request" | "inventory.import.result" => {
                let actual = if vector.kind.ends_with(".request") {
                    InventoryImportRequest::from_json(vector.input.as_bytes())
                        .and_then(|value| value.to_json())
                } else {
                    InventoryImportResult::from_json(vector.input.as_bytes())
                        .and_then(|value| value.to_json())
                };
                if vector.expected == "rejected" {
                    assert!(actual.is_err(), "{}", vector.id);
                } else {
                    assert_eq!(actual.unwrap(), vector.expected.as_bytes(), "{}", vector.id);
                }
            }
            "inventory.import.binding" => {
                let value: Value = serde_json::from_str(&vector.input).unwrap();
                let request = InventoryImportRequest::from_json(
                    &serde_json::to_vec(&value["request"]).unwrap(),
                )
                .unwrap();
                let result = InventoryImportResult::from_json(
                    &serde_json::to_vec(&value["result"]).unwrap(),
                )
                .unwrap();
                assert_eq!(
                    result.validate_for_request(&request).is_ok(),
                    vector.expected == "accepted",
                    "{}",
                    vector.id
                );
            }
            "inventory.import.bound" => {
                let value: Value = serde_json::from_str(&vector.input).unwrap();
                let size = usize::try_from(value["bytes"].as_u64().unwrap()).unwrap();
                let kind = value["kind"].as_str().unwrap();
                let accepted = if kind == "csv" {
                    let mut input = format!(
                        "{HEADER}\n{}",
                        format!("{},h,,u,\n", "x".repeat(10_480)).repeat(99)
                    );
                    input.push_str(&"x".repeat(size - input.len() - 6));
                    input.push_str(",h,,u,");
                    assert_eq!(input.len(), size);
                    parse_inventory_csv(input.as_bytes()).is_ok()
                } else {
                    let base = value["base"].as_str().unwrap();
                    let input = " ".repeat(size - base.len()) + base;
                    if kind == "request" {
                        InventoryImportRequest::from_json(input.as_bytes()).is_ok()
                    } else {
                        InventoryImportResult::from_json(input.as_bytes()).is_ok()
                    }
                };
                assert_eq!(accepted, vector.expected == "accepted", "{}", vector.id);
            }
            _ => panic!("unknown import vector kind"),
        }
    }
}
