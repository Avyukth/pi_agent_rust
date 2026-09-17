use super::*;

fn runtime() -> asupersync::runtime::Runtime {
    asupersync::runtime::RuntimeBuilder::new()
        .enable_parking(false).worker_threads(1).blocking_threads(1, 8).build().expect("runtime")
}

fn run(tool: &DebugTool, runtime: &asupersync::runtime::Runtime, input: Value) -> Result<Value> {
    runtime.block_on(tool.execute("debug-test",input,None)).map(|output|output.details.expect("details"))
}

#[test]
fn missing_session_is_named_error() {
    let temp = tempfile::tempdir().expect("tempdir");
    let error = run(&DebugTool::new(temp.path(),None),&runtime(),json!({"action":"threads"})).unwrap_err();
    assert!(error.to_string().contains("DAP_NO_SESSION"));
}

#[test]
fn launch_without_program_is_usage_error() {
    let temp = tempfile::tempdir().expect("tempdir");
    let error = run(&DebugTool::new(temp.path(),None),&runtime(),json!({"action":"launch"})).unwrap_err();
    assert!(error.to_string().contains("DAP_USAGE"));
}

#[test]
fn missing_target_is_named_error() {
    let temp = tempfile::tempdir().expect("tempdir");
    let error = run(&DebugTool::new(temp.path(),None),&runtime(),json!({"action":"launch","program":"missing.py"})).unwrap_err();
    assert!(error.to_string().contains("DAP_TARGET_MISSING"));
}

#[test]
fn sessions_empty_without_session() {
    let temp = tempfile::tempdir().expect("tempdir");
    let output = run(&DebugTool::new(temp.path(),None),&runtime(),json!({"action":"sessions"})).unwrap();
    assert_eq!(output["sessions"],json!([]));
}

#[cfg(unix)]
fn fixture(path: &Path, mode: &str) -> Option<DebugTool> {
    let python = std::env::var_os("PATH").and_then(|paths| {
        std::env::split_paths(&paths).map(|dir|dir.join("python3")).find(|path|path.is_file())
    });
    let Some(python) = python else {
        assert!(std::env::var_os("PI_DEBUG_REQUIRE_PROTOCOL").is_none(), "python3 required for DAP protocol tests");
        eprintln!("skip: python3 is absent; no DAP protocol fixture ran");
        return None;
    };
    let adapter = path.join("test-adapter.py");
    std::fs::write(&adapter,include_str!("test_adapter.py")).unwrap();
    std::fs::write(path.join("program.py"),"value = 1\n").unwrap();
    Some(DebugTool::new(path,None).with_adapters(vec![AdapterSpec {
        id:"protocol-fixture".into(), command_candidates:vec![python.display().to_string()],
        adapter_args:vec!["-I".into(),"-u".into(),adapter.display().to_string(),mode.into()],
        languages:vec!["python"], install_hint:"test fixture".into(),
    }]))
}

#[cfg(unix)]
fn launch(tool: &DebugTool, runtime: &asupersync::runtime::Runtime) {
    run(tool,runtime,json!({"action":"launch","program":"program.py","adapter":"protocol-fixture"})).unwrap();
}

#[cfg(unix)]
#[test]
fn breakpoint_workflow_preserves_all_families_and_removes_individual_entries() {
    let temp = tempfile::tempdir().unwrap();
    let Some(tool) = fixture(temp.path(),"normal") else { return; };
    let runtime = runtime();
    launch(&tool,&runtime);
    for line in [10,20] {
        let output = run(&tool,&runtime,json!({"action":"set_breakpoint","file":"program.py","line":line})).unwrap();
        assert_eq!(output["verified"],true);
    }
    let output = run(&tool,&runtime,json!({"action":"set_breakpoint","file":"./program.py","line":10,"condition":"value > 2","logMessage":"value={value}"})).unwrap();
    assert_eq!(output["count"],2);
    assert_eq!(output["breakpoint"]["condition"],"value > 2");
    let removed = run(&tool,&runtime,json!({"action":"remove_breakpoint","file":"program.py","line":10})).unwrap();
    assert_eq!(removed["breakpoints"][0]["line"],20);
    for (set,remove,field,first,second) in [
        ("set_function_breakpoint","remove_function_breakpoint","name","first","second"),
        ("set_instruction_breakpoint","remove_instruction_breakpoint","reference","0x10","0x20"),
        ("set_data_breakpoint","remove_data_breakpoint","dataId","watch-A","watch-B"),
    ] {
        for value in [first,second] {
            let mut input = json!({"action":set});
            input[field] = json!(value);
            run(&tool,&runtime,input).unwrap();
        }
        let mut input = json!({"action":remove});
        input[field] = json!(first);
        assert_eq!(run(&tool,&runtime,input).unwrap()["count"],1);
    }
    let info = run(&tool,&runtime,json!({"action":"data_breakpoint_info","name":"value","variablesReference":41,"frameId":21})).unwrap();
    assert_eq!(info["result"]["dataId"],"opaque-watch-id");
    let inventory = run(&tool,&runtime,json!({"action":"list_breakpoints"})).unwrap();
    assert_eq!(inventory["groups"].as_array().unwrap().len(),4);
    run(&tool,&runtime,json!({"action":"terminate"})).unwrap();
}

#[cfg(unix)]
#[test]
fn launch_configures_initial_breakpoints_before_configuration_done() {
    let temp = tempfile::tempdir().unwrap();
    let Some(tool) = fixture(temp.path(),"normal") else { return; };
    let runtime = runtime();
    let output = run(&tool,&runtime,json!({"action":"launch","program":"program.py","adapter":"protocol-fixture",
        "initialBreakpoints":[{"file":"program.py","line":10},{"file":"./program.py","line":20}],"exceptionFilters":["raised"]})).unwrap();
    assert_eq!(output["execution"]["reason"],"entry");
    let captured = run(&tool,&runtime,json!({"action":"custom_request","command":"capture"})).unwrap();
    let requests = captured["result"]["requests"].as_array().unwrap();
    let commands: Vec<_> = requests.iter().map(|request|request["command"].as_str().unwrap()).collect();
    assert_eq!(&commands[..5],&["initialize","launch","setBreakpoints","setExceptionBreakpoints","configurationDone"]);
    assert_eq!(requests[2]["arguments"]["breakpoints"].as_array().unwrap().len(),2);
    let error = run(&tool,&runtime,json!({"action":"launch","program":"program.py","adapter":"protocol-fixture"})).unwrap_err();
    assert!(error.to_string().contains("DAP_SESSION_EXISTS"));
    run(&tool,&runtime,json!({"action":"terminate"})).unwrap();
}

#[cfg(unix)]
#[test]
fn configuration_failure_does_not_publish_a_session_or_ignore_adapter_errors() {
    let temp = tempfile::tempdir().unwrap();
    let Some(tool) = fixture(temp.path(),"configuration_error") else { return; };
    let runtime = runtime();
    let error = run(&tool,&runtime,json!({"action":"launch","program":"program.py","adapter":"protocol-fixture"})).unwrap_err();
    assert!(error.to_string().contains("configuration rejected"));
    assert_eq!(run(&tool,&runtime,json!({"action":"sessions"})).unwrap()["sessions"],json!([]));
}

#[cfg(unix)]
#[test]
fn unsupported_configuration_done_is_not_sent() {
    let temp = tempfile::tempdir().unwrap();
    let Some(tool) = fixture(temp.path(),"no_configuration_done") else { return; };
    let runtime = runtime();
    launch(&tool,&runtime);
    let captured = run(&tool,&runtime,json!({"action":"custom_request","command":"capture"})).unwrap();
    assert!(!captured["result"]["requests"].as_array().unwrap().iter().any(|request|request["command"]=="configurationDone"));
    run(&tool,&runtime,json!({"action":"terminate"})).unwrap();
}

#[cfg(unix)]
#[test]
fn stepping_waits_for_a_fresh_stop_in_either_reply_order() {
    for mode in ["normal","stop_before_reply"] {
        let temp = tempfile::tempdir().unwrap();
        let Some(tool) = fixture(temp.path(),mode) else { return; };
        let runtime = runtime();
        launch(&tool,&runtime);
        let output = run(&tool,&runtime,json!({"action":"step_over"})).unwrap();
        assert_eq!(output["stopped"]["reason"],"step", "must not return the old entry stop");
        assert_eq!(output["stopped"]["threadId"],8);
        run(&tool,&runtime,json!({"action":"continue"})).unwrap();
        let error = run(&tool,&runtime,json!({"action":"stack_trace"})).unwrap_err();
        assert!(error.to_string().contains("DAP_STATE_RUNNING"));
        run(&tool,&runtime,json!({"action":"terminate"})).unwrap();
    }
}

#[cfg(unix)]
#[test]
fn failed_breakpoint_updates_keep_the_acknowledged_set_and_mark_uncertainty() {
    let temp = tempfile::tempdir().unwrap();
    let Some(tool) = fixture(temp.path(),"normal") else { return; };
    let runtime = runtime();
    launch(&tool,&runtime);
    run(&tool,&runtime,json!({"action":"set_breakpoint","file":"program.py","line":10})).unwrap();
    for rejected in [13,99] {
        assert!(run(&tool,&runtime,json!({"action":"set_breakpoint","file":"program.py","line":rejected})).is_err());
        let inventory = run(&tool,&runtime,json!({"action":"list_breakpoints"})).unwrap();
        assert_eq!(inventory["groups"][0]["synchronized"],false);
        assert_eq!(inventory["groups"][0]["requested"],json!([{"line":10}]));
    }
    let repaired = run(&tool,&runtime,json!({"action":"set_breakpoint","file":"program.py","line":20})).unwrap();
    assert_eq!(repaired["count"],2);
    assert_eq!(repaired["synchronized"],true);
    run(&tool,&runtime,json!({"action":"terminate"})).unwrap();
}

#[cfg(unix)]
#[test]
fn evaluation_retains_expandable_references_and_variable_paging() {
    let temp = tempfile::tempdir().unwrap();
    let Some(tool) = fixture(temp.path(),"normal") else { return; };
    let runtime = runtime();
    launch(&tool,&runtime);
    let output = run(&tool,&runtime,json!({"action":"evaluate","expression":"value"})).unwrap();
    assert_eq!(output["variablesReference"],66);
    assert_eq!(output["memoryReference"],"0x100");
    run(&tool,&runtime,json!({"action":"variables","variablesReference":66,"start":1,"limit":2,"filter":"named"})).unwrap();
    let captured = run(&tool,&runtime,json!({"action":"custom_request","command":"capture"})).unwrap();
    let requests = captured["result"]["requests"].as_array().unwrap();
    let variables = requests.iter().find(|request|request["command"]=="variables").unwrap();
    assert_eq!(variables["arguments"],json!({"variablesReference":66,"start":1,"count":2,"filter":"named"}));
    run(&tool,&runtime,json!({"action":"terminate"})).unwrap();
}
